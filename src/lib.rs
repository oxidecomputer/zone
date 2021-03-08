// Copyright 2021 Oxide Computer Company

//! APIs for interacting with the Solaris zone facility.

use itertools::Itertools;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::string::ToString;
use thiserror::Error;
use zone_cfg_derive::Resource;

const PFEXEC: &str = "/bin/pfexec";
const ZONENAME: &str = "/usr/bin/zonename";
const ZONEADM: &str = "/usr/sbin/zoneadm";
const ZONECFG: &str = "/usr/sbin/zonecfg";
const ZLOGIN: &str = "/usr/sbin/zlogin";

/// The error type for parsing a bad status code while reading stdout.
#[derive(Error, Debug)]
#[error("{0}")]
pub struct CommandOutputError(String);

trait OutputExt {
    fn read_stdout(&self) -> Result<String, CommandOutputError>;
}

impl OutputExt for std::process::Output {
    fn read_stdout(&self) -> Result<String, CommandOutputError> {
        let stdout = String::from_utf8_lossy(&self.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&self.stderr).trim().to_string();

        if !self.status.success() {
            let exit_code = self
                .status
                .code()
                .map(|code| format!("{}", code))
                .unwrap_or_else(|| "<No exit code>".to_string());
            return Err(CommandOutputError(format!(
                "exit code {}\nstdout:\n{}\nstderr:\n{}",
                exit_code, stdout, stderr
            )));
        }
        Ok(stdout)
    }
}

#[derive(Error, Debug)]
pub enum ZoneError {
    /// Failure to parse the output of a query command.
    #[error("Failed to parse output: {0}")]
    Parse(String),

    /// Failure to execute a subcommand.
    #[error("Failed to execute command: {0}")]
    Command(std::io::Error),

    /// Failure reading a command's stdout (or non-zero error code).
    #[error("Failed to parse command output: {0}")]
    CommandOutput(#[from] CommandOutputError),
}

// zoneadm -z zonename [-u uuid-match] subcommand [subcommand_options]

// - zoneadm list
//   -c --> All *configured* zones
//   -i --> All *installed* zones
//   (neither c/i) --> All *running* zones
//   -n --> Do not include global zone
//   -v --> Human readable output
//   -p --> Machine readable output (colon separated)

enum PropertyName {
    Implicit,
    Explicit(String),
}

/// Describes a property name/value pair which can be provided
/// to zonecfg.
struct Property {
    name: PropertyName,
    value: String,
}

trait PropertyExtractor {
    fn get_properties(&self) -> Vec<Property>;
    fn get_clearables(&self) -> Vec<PropertyName>;
}

macro_rules! implement_implicit_extractor {
    ($t:ty) => {
        impl PropertyExtractor for $t {
            fn get_properties(&self) -> Vec<Property> {
                vec![Property {
                    name: PropertyName::Implicit,
                    value: self.to_string(),
                }]
            }
            fn get_clearables(&self) -> Vec<PropertyName> {
                vec![]
            }
        }
    };
}

implement_implicit_extractor!(bool);
implement_implicit_extractor!(u8);
implement_implicit_extractor!(u16);
implement_implicit_extractor!(u32);
implement_implicit_extractor!(u64);
implement_implicit_extractor!(i8);
implement_implicit_extractor!(i16);
implement_implicit_extractor!(i32);
implement_implicit_extractor!(i64);
implement_implicit_extractor!(f32);
implement_implicit_extractor!(f64);
implement_implicit_extractor!(String);

impl<T: std::fmt::Display> PropertyExtractor for Option<T> {
    fn get_properties(&self) -> Vec<Property> {
        if let Some(value) = self {
            vec![Property {
                name: PropertyName::Implicit,
                value: value.to_string(),
            }]
        } else {
            vec![]
        }
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        if let None = self {
            vec![PropertyName::Implicit]
        } else {
            vec![]
        }
    }
}

/// Vec represents the "List" objects within zonecfg.
impl<T: std::fmt::Display> PropertyExtractor for Vec<T> {
    fn get_properties(&self) -> Vec<Property> {
        let values: String = self
            .iter()
            .map(|val| val.to_string())
            .collect::<Vec<String>>()
            .join(",");
        vec![Property {
            name: PropertyName::Implicit,
            value: format!("[{}]", values),
        }]
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        vec![]
    }
}

/// BTreeSet represents "simple" values in zonecfg.
///
/// We usually don't need the ordering, but using BTreeSet
/// keeps the order consistent.
impl<T: std::fmt::Display> PropertyExtractor for BTreeSet<T> {
    fn get_properties(&self) -> Vec<Property> {
        if self.is_empty() {
            return vec![];
        }

        let values: String = self
            .iter()
            .map(|val| val.to_string())
            .collect::<Vec<String>>()
            .join(",");
        vec![Property {
            name: PropertyName::Implicit,
            value: format!("{}", values),
        }]
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        if self.is_empty() {
            vec![PropertyName::Implicit]
        } else {
            vec![]
        }
    }
}

/// Identifies the source of a zone's IP stack.
pub enum IpType {
    /// The IP stack is shared with thte global zone.
    Shared,
    /// The IP stack is to be instantiated exclusively to the zone.
    Exclusive,
}

impl std::fmt::Display for IpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            IpType::Shared => write!(f, "shared"),
            IpType::Exclusive => write!(f, "exclusive"),
        }
    }
}

implement_implicit_extractor!(IpType);

#[derive(Resource)]
pub struct Global {
    #[resource(global)]

    /// The name of the zone.
    #[resource(name = "zonename")]
    pub name: String,
    /// The path to the zone's filesystem.
    #[resource(name = "zonepath")]
    pub path: String,
    /// Boolean indicating if the zone should be automatically
    /// booted at system boot.
    ///
    /// Requires the zone service to be enabled to operate.
    pub autoboot: bool,
    /// Arguments passed to the zone bootup.
    pub bootargs: Option<String>,
    /// The name of the resoure pool bound to this zone.
    ///
    /// Incompatible with the dedicated-cpu resource.
    pub pool: Option<String>,
    /// The maximum set of privileges any process in this zone can obtain.
    pub limitpriv: BTreeSet<String>,
    /// The zone's brand type.
    pub brand: String,
    /// 32-bit host identifier.
    pub hostid: Option<u32>,
    /// The way in which IP is shared with the global zone.
    #[resource(name = "ip-type")]
    pub ip_type: IpType,
    /// The number of Fair Share Scheduler (FSS) shares to allocate to this
    /// zone.
    ///
    /// This property is incompatible with the dedicated-cpu resource.
    #[resource(name = "cpu-shares")]
    pub cpu_shares: Option<u32>,
    /// The maximum number of LWPs (lightweight processes) available to this
    /// zone.
    #[resource(name = "max-lwps")]
    pub max_lwps: Option<u32>,
    /// The maximum number of message queue IDs allowed for this zone.
    #[resource(name = "max-msg-ids")]
    pub max_message_ids: Option<u32>,
    /// The maximum number of semaphore IDs allowed for this zone.
    #[resource(name = "max-sem-ids")]
    pub max_semaphore_ids: Option<u32>,
    /// The maximum number of shared memory IDs allowed for this zone.
    #[resource(name = "max-shm-ids")]
    pub max_shared_memory_ids: Option<u32>,
    /// The maximum amount of shared memory allowed for this zone, in bytes.
    #[resource(name = "max-shm-memory")]
    pub max_shared_memory: Option<u64>,
    /// Specifies the scheduling class used for processes running in a zone.
    ///
    /// If unspecified, it is inferred as follows:
    /// - If the `cpu-shares` property has been set, FSS is used.
    /// - If `cpu-shares` is not set and the `pool` property references a pool
    /// that has a default scheduling class, that class is used.
    /// - Otherwise, the system's default scheduling class is used.
    #[resource(name = "scheduling-class")]
    pub scheduling_class: Option<String>,
    /// A comma-separated list of additional filesystems that may be mounted
    /// within the zone (for example, "ufs,pcfs").
    #[resource(name = "fs-allowed")]
    pub fs_allowed: BTreeSet<String>,
}

/// Values for the resource "fs".
#[derive(Default, Resource)]
pub struct Fs {
    /// Type of filesystem mounted within the zone.
    // TODO: Enum?
    #[resource(name = "type", selector)]
    pub ty: String,
    /// Directory (in the zone) where the filesystem will be mounted.
    #[resource(selector)]
    pub dir: String,
    /// Directory (in the GZ) which will be mounted into the zone.
    #[resource(selector)]
    pub special: String,
    pub raw: Option<String>,
    // TODO: Enum?
    pub options: Vec<String>,
}

#[derive(Default, Resource)]
pub struct Net {
    /// Network interface name (format matching ifconfig(1M)).
    #[resource(selector)]
    pub physical: String,

    /// Network address of the network interface.
    ///
    /// Must be set for a shared-IP zone.
    /// Should not be set for exclusive-IP zones.
    pub address: Option<String>,

    /// If set, the zone administrator will only be able to
    /// configure the interface with the specified address.
    ///
    /// Should not be shared for shared-IP zone.
    #[resource(name = "allowed-address")]
    pub allowed_address: Option<String>,

    /// The default router.
    ///
    /// Optional for a shared-IP zone.
    /// Should not be set for exclusive-IP zones.
    #[resource(name = "defrouter")]
    pub default_router: Option<String>,
}

#[derive(Default, Resource)]
pub struct Device {
    /// Device name to match
    pub name: String,
}

#[derive(Default, Resource)]
pub struct Rctl {
    /// The name of a resource control object.
    #[resource(selector)]
    pub name: String,
    /// The priv/limit/action triple of an rctl.
    pub value: String,
}

/// Describes both the type and value of an attribute.
pub enum AttributeValue {
    Int(i64),
    UInt(u64),
    Boolean(bool),
    String(String),
}

impl AttributeValue {
    fn type_str(&self) -> String {
        match self {
            AttributeValue::Int(_) => "int",
            AttributeValue::UInt(_) => "uint",
            AttributeValue::Boolean(_) => "boolean",
            AttributeValue::String(_) => "string",
        }
        .to_string()
    }

    fn value_str(&self) -> String {
        match self {
            AttributeValue::Int(n) => n.to_string(),
            AttributeValue::UInt(n) => n.to_string(),
            AttributeValue::Boolean(b) => b.to_string(),
            AttributeValue::String(s) => s.clone(),
        }
    }
}

impl PropertyExtractor for AttributeValue {
    fn get_properties(&self) -> Vec<Property> {
        vec![
            Property {
                name: PropertyName::Explicit("type".to_string()),
                value: self.type_str(),
            },
            Property {
                name: PropertyName::Explicit("value".to_string()),
                value: self.value_str(),
            },
        ]
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        vec![]
    }
}

/// Represents the resource of a generic attribute.
#[derive(Resource)]
pub struct Attr {
    #[resource(selector)]
    pub name: String,
    pub value: AttributeValue,
}

#[derive(Default, Resource)]
pub struct Dataset {
    /// The name of a ZFS dataset to be accessed from within the zone.
    pub name: String,
}

/// Resource indicating a dedicated CPU for zone usage.
#[derive(Default, Resource)]
pub struct DedicatedCpu {
    /// The number of CPUs which should be assigned to this zone
    /// for exclusive use.
    ///
    /// Can specify a single value or a range (i.e. 1-4).
    pub ncpus: String,
    pub importance: Option<String>,
}

/// Resource indicating the limit on the amount of memory that can be used by a zone.
#[derive(Default, Resource)]
pub struct CappedMemory {
    pub physical: Option<String>,
    pub swap: Option<String>,
    pub locked: Option<String>,
}

/// Resource indicating the amount of CPU time that can be used by a zone.
#[derive(Default, Resource)]
pub struct CappedCpu {
    /// The percentage of a single CPU that can be used
    /// by all user threads in a zone. As an example, "1.0" represents
    /// 100% of a single CPU.
    pub ncpus: f64,
}

/// Description of per-process security and exploit mitigation features.
///
/// Context: https://illumos.org/man/5/security-flags
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecurityFlag {
    /// Address SPace Layout Randomization.
    Aslr,
    /// Mappings with an address of "zero" are forbidden.
    ForbidNullMap,
    /// The stack will be mapped without executable permission.
    NonExecutableStack,
}

impl std::fmt::Display for SecurityFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            SecurityFlag::Aslr => write!(f, "ASLR"),
            SecurityFlag::ForbidNullMap => write!(f, "FORBIDNULLMAP"),
            SecurityFlag::NonExecutableStack => write!(f, "NOEXECSTACK"),
        }
    }
}

/// Resource indicating the security flags associated with a zone.
#[derive(Default, Resource)]
pub struct SecurityFlags {
    /// The lower limit of security flags which can be set for the zone.
    pub lower: BTreeSet<SecurityFlag>,
    /// The set of flags all zone processes inherit.
    pub default: BTreeSet<SecurityFlag>,
    /// The upper limit of security flags which can be set for the zone.
    pub upper: BTreeSet<SecurityFlag>,
}

/// Zone authorizations which may be granted to a user.
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Auths {
    /// Enables the user to zlogin to the zone, being prompted for authz.
    Login,
    /// Enables the user to install, update, boot, or halt the zone.
    Manage,
    /// Alows the user to install a new zone using this zone as a source.
    CloneFrom,
}

impl std::fmt::Display for Auths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Auths::Login => write!(f, "login"),
            Auths::Manage => write!(f, "manage"),
            Auths::CloneFrom => write!(f, "clonefrom"),
        }
    }
}

/// Delegation of zone administration to a named user.
#[derive(Default, Resource)]
pub struct Admin {
    /// The name of the user to receive authorization.
    #[resource(selector)]
    pub user: String,
    pub auths: BTreeSet<Auths>,
}

// zonecfg -z zonename subcommand
//
// Don't impact running zones; reboot necessary to take effect.

/// Entry point for `zonecfg` commands.
pub struct Config {
    /// Name of the zone.
    name: String,
    /// Arguments to be passed to zonecfg.
    args: Vec<String>,
}

/// Describes the options for creation a new zone.
pub enum CreationOptions {
    /// Configures detached zone onto a new host.
    ///
    /// The provided path is the zonepath location of the detached zone that has
    /// been moved onto this new host.
    FromDetached(PathBuf),
    /// Creates a blank configuration.
    Blank,
    /// Creates a configuration based on the system defaults.
    Default,
    /// Creates a configuration identical to another configured zone.
    /// The supplied string is the name of the zone to copy.
    Template(String),
}

impl Config {
    fn push<S: AsRef<str>>(&mut self, value: S) {
        self.args.push(value.as_ref().into());
    }

    /// Instantiate a zone configuration object, wrapping an existing zone.
    pub fn new<S: AsRef<str>>(name: S) -> Config {
        Config {
            name: name.as_ref().into(),
            args: vec![],
        }
    }

    /// Creates a new zone with the provided `name`.
    ///
    /// - `overwrite` specifies if the new zone should overwrite
    /// any existing zone with the same name, if one exists.
    /// - `options` specifies background information about the zone.
    pub fn create<S: AsRef<str>>(name: S, overwrite: bool, options: CreationOptions) -> Config {
        let overwrite_flag = if overwrite {
            "-F".to_string()
        } else {
            "".to_string()
        };
        let options = match options {
            CreationOptions::FromDetached(path) => {
                format!("-a {}", path.into_os_string().to_string_lossy())
            }
            CreationOptions::Blank => format!("-b"),
            CreationOptions::Default => "".to_string(),
            CreationOptions::Template(zone) => format!("-t {}", zone),
        };

        let mut cfg = Self::new(name);
        cfg.push(format!("create {} {}", overwrite_flag, options));
        cfg
    }

    /// Enqueues a command to export the zone configuration to a specified path.
    pub fn export(&mut self, p: impl AsRef<Path>) {
        self.push(format!("export -f {}", p.as_ref().to_string_lossy()));
    }

    /// Executes the queued commands for the zone, and clears the
    /// current queued arguments.
    pub fn run(&mut self) -> Result<String, ZoneError> {
        let separator = ";".to_string();
        let args = self.args.iter().intersperse(&separator);

        let out = std::process::Command::new(PFEXEC)
            .env_clear()
            .arg(ZONECFG)
            .arg("-z")
            .arg(&self.name)
            .args(args)
            .output()
            .map_err(ZoneError::Command)?
            .read_stdout()?;
        self.args.clear();
        Ok(out)
    }

    // TODO:
    //
    // - commit
    //   COMMIT THE CURRENT CONFIG to storage.
    //   Attempted automatically when a zonecfg session ends.
    //   (XXX: Maybe ignore this?)
    //
    // - info (lots of options)
    //  QUERIES about the current config.
    //
    // - verify
    //  CHECKS that the current config is correct (all required props spec'd).
}

/// Returns the name of the current zone, if one exists.
pub fn current() -> Result<String, ZoneError> {
    Ok(std::process::Command::new(ZONENAME)
        .env_clear()
        .output()
        .map_err(ZoneError::Command)?
        .read_stdout()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_zone() {
        let zone = current().unwrap();
        assert_eq!("global", zone);
    }

    #[test]
    fn test_cfg_fs() {
        let mut cfg = Config::new("my-zone");

        let fs = Fs {
            ty: "my-type".to_string(),
            dir: "/path/to/dir".to_string(),
            special: "/path/to/special".to_string(),
            ..Default::default()
        };

        cfg.add_fs(&fs)
            // Set a mandatory field.
            .set_dir("/path/to/other/dir")
            // Clear and set an optional field.
            .set_raw(None)
            .set_raw(Some("/raw".to_string()))
            // Set a list field.
            .set_options(vec!["abc".to_string(), "def".to_string()]);

        assert_eq!(
            cfg.args,
            &[
                // Initial resource creation.
                "add fs",
                "set type=my-type",
                "set dir=/path/to/dir",
                "set special=/path/to/special",
                "set options=[]",
                // Set mandatory field.
                "set dir=/path/to/other/dir",
                // Clear and set optional fied.
                "clear raw",
                "set raw=/raw",
                // Set a list field.
                "set options=[abc,def]",
                "end"
            ]
        );
    }

    #[test]
    fn test_cfg_attr() {
        let mut cfg = Config::new("my-zone");

        let attr = Attr {
            name: "my-attr".to_string(),
            value: AttributeValue::UInt(10),
        };

        cfg.add_attr(&attr);

        assert_eq!(
            cfg.args,
            &[
                "add attr",
                "set name=my-attr",
                "set type=uint",
                "set value=10",
                "end"
            ]
        );
    }

    #[test]
    fn test_cfg_security_flags() {
        let mut cfg = Config::new("my-zone");

        let mut default = BTreeSet::new();
        default.insert(SecurityFlag::Aslr);
        default.insert(SecurityFlag::ForbidNullMap);

        let security_flags = SecurityFlags {
            default,
            ..Default::default()
        };

        let mut lower = BTreeSet::new();
        lower.insert(SecurityFlag::Aslr);

        cfg.add_security_flags(&security_flags).set_lower(lower);

        assert_eq!(
            cfg.args,
            &[
                "add security-flags",
                "set default=ASLR,FORBIDNULLMAP",
                "set lower=ASLR",
                "end"
            ]
        );
    }

    #[test]
    fn test_cfg_global() {
        let mut cfg = Config::new("my-zone");

        let mut fs_allowed = BTreeSet::new();
        fs_allowed.insert("ufs".to_string());
        fs_allowed.insert("pcfs".to_string());

        cfg.get_global()
            .set_name("my-new-zone")
            .set_autoboot(false)
            .set_limitpriv(BTreeSet::new())
            .set_fs_allowed(fs_allowed)
            .set_pool(Some("my-pool".to_string()))
            .set_pool(None)
            .set_ip_type(IpType::Exclusive);

        assert_eq!(
            cfg.args,
            &[
                "set zonename=my-new-zone",
                "set autoboot=false",
                "clear limitpriv",
                "set fs-allowed=pcfs,ufs",
                "set pool=my-pool",
                "clear pool",
                "set ip-type=exclusive",
            ]
        );
    }

    #[test]
    fn test_cfg_man_page_example() {
        let mut cfg = Config::create("myzone", true, CreationOptions::Default);
        cfg.get_global()
            .set_path("/export/home/myzone")
            .set_autoboot(true);
        cfg.add_fs(
            &Fs {
                ty: "lofs".to_string(),
                dir: "/usr/local".to_string(),
                special: "/opt/local".to_string(),
                options: vec!["ro".to_string(), "nodevices".to_string()],
                ..Default::default()
            }
        );
        cfg.add_net(
            &Net {
                address: Some("192.168.0.1/24".to_string()),
                physical: "eri0".to_string(),
                ..Default::default()
            }
        );
        cfg.add_net(
            &Net {
                address: Some("192.168.1.2/24".to_string()),
                physical: "eri0".to_string(),
                ..Default::default()
            }
        );
        cfg.add_net(
            &Net {
                address: Some("192.168.2.3/24".to_string()),
                physical: "eri0".to_string(),
                ..Default::default()
            }
        );
        cfg.get_global().set_cpu_shares(5);
        cfg.add_capped_memory(
            &CappedMemory {
                physical: Some("50m".to_string()),
                swap: Some("100m".to_string()),
                ..Default::default()
            }
        );

        cfg.run().unwrap();
    }
}

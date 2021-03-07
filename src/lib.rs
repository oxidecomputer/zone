// Copyright 2021 Oxide Computer Company

//! APIs for interacting with the Solaris zone facility.

// TODO: Modules to designate properties vs scopes vs other?

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::string::ToString;
use thiserror::Error;
use zone_cfg_derive::Resource;

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
                vec![
                    Property {
                        name: PropertyName::Implicit,
                        value: self.to_string(),
                    }
                ]
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
           vec![
               Property {
                   name: PropertyName::Implicit,
                   value: value.to_string(),
               }
           ]
        } else {
           vec![]
        }
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        if let None = self {
            vec![
                PropertyName::Implicit
            ]
        } else {
            vec![]
        }
    }
}

/// Vec represents the "List" objects within zonecfg.
impl<T: std::fmt::Display> PropertyExtractor for Vec<T> {
    fn get_properties(&self) -> Vec<Property> {
        let values: String = self.iter()
            .map(|val| val.to_string())
            .collect::<Vec<String>>()
            .join(",");
        vec![
            Property {
                name: PropertyName::Implicit,
                value: format!("[{}]", values),
            }
        ]
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

        let values: String = self.iter()
            .map(|val| val.to_string())
            .collect::<Vec<String>>()
            .join(",");
        vec![
            Property {
                name: PropertyName::Implicit,
                value: format!("{}", values),
            }
        ]
    }
    fn get_clearables(&self) -> Vec<PropertyName> {
        vec![]
    }
}

pub enum IpType {
    Shared,
    Exclusive,
}

#[derive(Default, Resource)]
pub struct Global {
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
    pub limitpriv: Vec<String>,
    /// The zone's brand type.
    pub brand: String,
    /// 32-bit host identifier.
    pub hostid: u32,

    /*
    // XXX
    /// The way in which IP is shared with the global zone.
    IP(IpType),
    CpuShares(String),
    MaxLwps(String),
    MaxMessageIDs(String),
    MaxSemIDs(String),
    MaxShmIDs(String),
    MaxShmMemory(String),
    SchedulingClass(String),
    FsAllowed(String),
    */
}

/// Values for the resource "fs".
#[derive(Default, Resource)]
pub struct Fs {
    /// Type of filesystem mounted within the zone.
    // TODO: Enum?
    #[resource(name = "type")]
    pub ty: String,
    /// Directory (in the zone) where the filesystem will be mounted.
    pub dir: String,
    /// Directory (in the GZ) which will be mounted into the zone.
    pub special: String,
    pub raw: Option<String>,
    // TODO: Enum?
    pub options: Vec<String>,
}

impl<'a> FsScope<'a> {
    fn select<S: AsRef<str>>(config: &'a mut Config, name: S) -> FsScope<'a> {
        config.args.push("select fs".to_string());
        config.args.push(format!("name={}", name.as_ref()));
        FsScope {
            config
        }
    }
}

#[derive(Resource)]
pub struct Net {
    /// Network interface name (format matching ifconfig(1M)).
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

#[derive(Resource)]
pub struct Device {
    /// Device name to match
    pub name: String,
}

#[derive(Resource)]
pub struct Rctl {
    /// The name of a resource control object.
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
        }.to_string()
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

impl<'a> AttrScope<'a> {
    // XXX can select by either name or value
    fn select<S: AsRef<str>>(config: &'a mut Config, name: S) -> AttrScope<'a> {
        config.args.push("select attr".to_string());
        config.args.push(format!("name={}", name.as_ref()));
        AttrScope {
            config
        }
    }
}

#[derive(Resource)]
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
#[derive(Resource)]
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
    pub user: String,
    pub auths: BTreeSet<Auths>,
}

// zonecfg -z zonename subcommand
//
// Don't impact running zones; reboot necessary to take effect.
pub struct Config {
    /// Name of the zone.
    name: String,
    /// Arguments to be passed to zonecfg.
    args: Vec<String>,
}

impl Config {
    pub fn new<S: AsRef<str>>(name: S) -> Config {
        Config {
            name: name.as_ref().into(),
            args: vec![],
        }
    }

    // XXX Could select by one or more attributes
    pub fn select_attr<S: AsRef<str>>(&mut self, name: S) -> AttrScope {
        AttrScope::select(self, name)
    }

    // XXX Could select by one or more attributes
    pub fn select_fs<S: AsRef<str>>(&mut self, name: S) -> FsScope {
        FsScope::select(self, name)
    }

    fn get_args(&mut self) -> &[String] {
        &self.args
    }


    // RESOURCE vs PROPERTY
    //
    // - RESOURCES are equivalent to SCOPES, they contain properties
    // - PROPERTIES are K/V pairs. Exist globally or in resource scope.


    // SCOPE MODIFIERS:
    // - add
    // - cancel (?)
    // - end
    // - select

    // TODO:
    //
    // - add <resource_type> (global scope)
    //   i.e. "add net; set physical=bge0; end"
    //   BEGIN SPECIFICATION for a resource type. Scope changed
    //   to that resource type.
    // - add <property_name property_value> (resource scope)
    //   ADD PROPERTY+VALUE.
    //
    // - cancel
    //   END RESOURCE SPEC, RESET SCOPE TO GLOBAL.
    //   Abandons partially specified resources.
    //   Only valid in resource scope.
    //   (XXX: Maybe ignore this?)
    //
    // - clear <property_name>
    //   CLEAR the value for the property
    //
    // - commit
    //   COMMIT THE CURRENT CONFIG to storage.
    //   Attempted automatically when a zonecfg session ends.
    //   (XXX: Maybe ignore this?)
    //
    // - create [-F] [ -a path | -b | -t template]
    //   CREATE a config for the zone.
    //   -F: Force (overwrites existing config)
    //   -a path: Configure detached zone on new host. Path is zonepath of
    //   detatched zone.
    //   -b: Blank config.
    //   -t template: Create config identical to another zone named template.
    //
    // - delete [-F]
    //  DELETES the config from memory + storage.
    //
    // - end
    //  ENDS resource spec. Only applicable when in resource scope.
    //
    // - export [-f output-file]
    //  EXPORTS config to stdout or a specified file.
    //  The output here is usable in a command file.
    //
    // - info (lots of options)
    //  QUERIES about the current config.
    //
    // - remove <resource-type>
    //  REMOVES the specified resource.
    //  (Global scope only)
    //
    // - select <resource-type> {property-name=property-value}
    //  SELECTS the resource of the given type which matches prop name/value
    //  pair. Scope changes to the resource type. Only works if the resource
    //  can be uniquely identified.
    //  (Global scope only)
    //
    // - set property-name=property-value
    //  SETS a given property to a given value.
    //
    // - verify
    //  CHECKS that the current config is correct (all required props spec'd).

}

// TODO: maybe a separate rctl library?

/// Returns the name of the current zone, if one exists.
pub fn current() -> Result<String, ZoneError> {
    Ok(std::process::Command::new("/usr/bin/zonename")
        .env_clear()
        .output()
        .map_err(ZoneError::Command)?
        .read_stdout()?)
}

#[cfg(test)]
mod tests {
    use super::*;

//    #[test]
//    fn test_current_zone() {
//        let zone = current().unwrap();
//        assert_eq!("global", zone);
//    }

    #[test]
    fn test_cfg_fs() {
        let mut cfg = Config::new("my-zone");

        let fs = Fs {
            ty: "my-type".to_string(),
            dir: "/path/to/dir".to_string(),
            special: "/path/to/special".to_string(),
            ..Default::default()
        };

        let mut fs_scope = cfg.add_fs(&fs);

        // Set a mandatory field.
        fs_scope.set_dir("/path/to/other/dir");

        // Clear and set an optional field.
        fs_scope.set_raw(None);
        fs_scope.set_raw(Some("/raw".to_string()));

        // Set a list field.
        fs_scope.set_options(vec!["abc".to_string(), "def".to_string()]);

        drop(fs_scope);

        assert_eq!(
            cfg.get_args(),
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

        let _ = cfg.add_attr(&attr);

        assert_eq!(
            cfg.get_args(),
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
    fn test_security_flags() {
        let mut cfg = Config::new("my-zone");

        let mut default = BTreeSet::new();
        default.insert(SecurityFlag::Aslr);
        default.insert(SecurityFlag::ForbidNullMap);

        let security_flags = SecurityFlags {
            default,
            ..Default::default()
        };

        let mut security_flags_scope = cfg.add_security_flags(&security_flags);

        let mut lower = BTreeSet::new();
        lower.insert(SecurityFlag::Aslr);
        security_flags_scope.set_lower(lower);

        drop(security_flags_scope);

        assert_eq!(
            cfg.get_args(),
            &[
                "add security-flags",
                "set default=ASLR,FORBIDNULLMAP",
                "set lower=ASLR",
                "end"
            ]
        );
    }
}

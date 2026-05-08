//! Internal helper macros for the Tuya protocol.
//!
//! Provides macros for defining protocol structures, command types, and error codes.

macro_rules! define_command_type {
    ($($name:ident = $val:expr),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[repr(u32)]
        pub enum CommandType {
            $($name = $val),*
        }

        impl CommandType {
            #[must_use]
            pub fn from_u32(val: u32) -> Option<Self> {
                match val {
                    $($val => Some(CommandType::$name)),*
                    , _ => None,
                }
            }
        }

        impl std::fmt::Display for CommandType {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}(0x{:02X})", self, *self as u32)
            }
        }
    };
}

macro_rules! define_version {
    ($($variant:ident = ($str_val:expr, $float_val:expr)),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Default, ::serde::Serialize, ::serde::Deserialize)]
        pub enum Version {
            #[default]
            Auto,
            $($variant),*
        }

        impl Version {
            #[must_use]
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::Auto => "Auto",
                    $(Self::$variant => $str_val),*
                }
            }

            #[must_use]
            pub fn as_bytes(&self) -> &'static [u8] {
                self.as_str().as_bytes()
            }

            #[must_use]
            pub fn val(&self) -> f32 {
                match self {
                    Version::Auto => 0.0,
                    $(Version::$variant => $float_val),*
                }
            }
        }

        /// Error returned when parsing a [`Version`] from a string fails.
        #[derive(Debug, Clone, PartialEq, Eq, ::thiserror::Error)]
        #[error("invalid Tuya protocol version: {0}")]
        pub struct ParseVersionError(pub String);

        impl std::str::FromStr for Version {
            type Err = ParseVersionError;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                match s {
                    "Auto" | "auto" | "" => Ok(Version::Auto),
                    $($str_val => Ok(Version::$variant)),*
                    , _ => Err(ParseVersionError(s.to_string())),
                }
            }
        }

        impl<'a> std::convert::TryFrom<&'a str> for Version {
            type Error = ParseVersionError;
            fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl std::convert::TryFrom<String> for Version {
            type Error = ParseVersionError;
            fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl std::fmt::Display for Version {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

macro_rules! define_error_codes {
    ($($name:ident = $code:expr => $msg:expr),* $(,)?) => {
        $(
            pub const $name: u32 = $code;
        )*

        #[must_use]
        pub fn get_error_message(code: u32) -> &'static str {
            match code {
                $(
                    $name => $msg,
                )*
                _ => "Unknown Error",
            }
        }
    };
}

pub(crate) use define_command_type;
pub(crate) use define_error_codes;
pub(crate) use define_version;

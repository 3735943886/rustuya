//! Internal helper macros for the Tuya protocol.
//!
//! Provides macros for defining protocol structures, command types, and error codes.

#[macro_export]
macro_rules! define_command_type {
    ($($name:ident = $val:expr),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[repr(u32)]
        pub enum CommandType {
            $($name = $val),*
        }

        impl CommandType {
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

#[macro_export]
macro_rules! define_version {
    ($($variant:ident = ($str_val:expr, $float_val:expr)),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Default, serde::Serialize, serde::Deserialize)]
        pub enum Version {
            #[default]
            Auto,
            $($variant),*
        }

        impl Version {
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::Auto => "Auto",
                    $(Self::$variant => $str_val),*
                }
            }

            pub fn as_bytes(&self) -> &'static [u8] {
                self.as_str().as_bytes()
            }

            pub fn val(&self) -> f32 {
                match self {
                    Version::Auto => 0.0,
                    $(Version::$variant => $float_val),*
                }
            }
        }

        impl std::str::FromStr for Version {
            type Err = String;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                match s {
                    "Auto" | "auto" | "" => Ok(Version::Auto),
                    $($str_val => Ok(Version::$variant)),*
                    , _ => Err(format!("Invalid version: {}", s)),
                }
            }
        }

        impl From<&str> for Version {
            fn from(s: &str) -> Self {
                s.parse().unwrap_or(Version::Auto)
            }
        }

        impl From<String> for Version {
            fn from(s: String) -> Self {
                s.parse().unwrap_or(Version::Auto)
            }
        }

        impl std::fmt::Display for Version {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }
    };
}

#[macro_export]
macro_rules! define_error_codes {
    ($($name:ident = $code:expr => $msg:expr),* $(,)?) => {
        $(
            pub const $name: u32 = $code;
        )*

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

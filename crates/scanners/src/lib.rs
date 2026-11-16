//! Local scanners. Each scanner only reads; none of them change anything on
//! the machine. They return plain data from `ga-core`; company classification
//! happens in `ga-report`, while risk that depends only on what a scanner
//! sees (extension permissions, setting values) is assessed here.

pub mod apps;
pub mod browsers;
pub mod extensions;
pub mod windows_privacy;

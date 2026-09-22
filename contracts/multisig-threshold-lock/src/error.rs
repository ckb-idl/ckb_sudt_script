use ckb_std::error::SysError;

#[repr(i8)]
pub enum Error { IndexOutOfBound = 1, ItemMissing, LengthNotEnough, Encoding, InvalidFd, WaitFailure, OtherEndClosed, MaxVmsSpawned, MaxFdsCreated, InvalidArgs = 10, ThresholdNotMet = 11, MissingWitness = 12 }

impl From<SysError> for Error {
    fn from(error: SysError) -> Self { match error {
        SysError::IndexOutOfBound => Self::IndexOutOfBound, SysError::ItemMissing => Self::ItemMissing,
        SysError::LengthNotEnough(_) => Self::LengthNotEnough, SysError::Encoding => Self::Encoding,
        SysError::InvalidFd => Self::InvalidFd, SysError::WaitFailure => Self::WaitFailure,
        SysError::OtherEndClosed => Self::OtherEndClosed, SysError::MaxVmsSpawned => Self::MaxVmsSpawned,
        SysError::MaxFdsCreated => Self::MaxFdsCreated, SysError::Unknown(code) => panic!("unexpected syscall error {code}"),
    }}
}

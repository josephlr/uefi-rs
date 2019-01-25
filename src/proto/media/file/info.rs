use super::FileAttribute;
use crate::data_types::chars::NUL_16;
use crate::table::runtime::Time;
use crate::{unsafe_guid, CStr16, Char16, Identify};
use core::convert::TryInto;
use core::ffi::c_void;
use core::mem;
use core::slice;

unsafe fn ptr_to_dst<'a, T: ?Sized>(ptr: *mut Char16, len: usize) -> &'a mut T {
    let mut fat_ptr = slice::from_raw_parts_mut(ptr, len);
    let info_ref_ptr = &mut fat_ptr as *mut &mut [Char16] as usize as *mut &mut T;
    *info_ref_ptr
}

/// Common trait for data structures that can be used with
/// `File::set_info()` or `File::set_info()`.
///
/// The long-winded name is needed because "FileInfo" is already taken by UEFI.
pub unsafe trait FileProtocolInfo: Identify {
    fn name(&self) -> &[Char16];
    fn name_mut(&mut self) -> &mut [Char16];

    fn name_str(&self) -> &CStr16 {
        unsafe { CStr16::from_ptr(&self.name()[0]) }
    }

    /// Required memory alignment for this type
    #[allow(clippy::invalid_ref)]
    fn alignment() -> usize {
        // Will not actually dereference null
        unsafe { mem::align_of_val(mem::zeroed::<&Self>()) }
    }

    /// Offset of name field
    #[allow(clippy::invalid_ref)]
    fn name_offset() -> usize {
        // Will not actually dereference null
        unsafe { mem::zeroed::<&Self>().name().as_ptr() as usize }
    }

    /// Assert that some storage is correctly aligned for this type
    fn assert_aligned(storage: &mut [u8]) {
        assert_eq!(
            (storage.as_ptr() as usize) % Self::alignment(),
            0,
            "The provided storage is not correctly aligned for this type"
        )
    }

    /// Turn an UEFI-provided pointer-to-base into a fat Rust reference
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn from_uefi<'ptr>(ptr: *mut c_void) -> &'ptr mut Self {
        let byte_ptr = ptr as *mut u8;
        let name_ptr = byte_ptr.add(Self::name_offset()) as *mut Char16;
        let name = CStr16::from_ptr(name_ptr);
        let name_len = name.to_u16_slice_with_nul().len();

        ptr_to_dst(ptr as *mut Char16, name_len)
    }

    /// Create our FileProtocolInfo in user-provided storage
    ///
    /// The structure will be created in-place within the provided storage
    /// buffer. The buffer must be large enough to hold the data structure,
    /// including a null-terminated UCS-2 version of the `name` string.
    ///
    /// The buffer must be correctly aligned. You can query the required
    /// alignment using the `alignment()` method.
    ///
    /// This method is unsafe as the output value will only have its name field
    /// initialized. Callers of this function should initiailze other fields.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn new_uninitialized<'buf>(
        storage: &'buf mut [u8],
        name: &str,
    ) -> core::result::Result<&'buf mut Self, FileInfoCreationError> {
        // Make sure that the storage is properly aligned
        Self::assert_aligned(storage);

        // Make sure that the storage is large enough for our needs
        let name_length_ucs2 = name.chars().count() + 1;
        let name_size = name_length_ucs2 * mem::size_of::<Char16>();
        let info_size = Self::name_offset() + name_size;
        if storage.len() < info_size {
            return Err(FileInfoCreationError::InsufficientStorage(info_size));
        }

        // At this point, our storage contains an uninitialized header, followed
        // by random rubbish. It is okay to reinterpret the rubbish as Char16s
        // because 1/we are going to overwrite it and 2/Char16 does not have a
        // Drop implementation. Thus, we are now ready to build a correctly
        // sized &mut Self and go back to the realm of safe code.
        debug_assert!(!mem::needs_drop::<Char16>());
        let info: &mut Self = ptr_to_dst(storage.as_mut_ptr() as *mut Char16, name_length_ucs2);
        debug_assert_eq!(info.name().len(), name_length_ucs2);

        // Write down the UCS-2 name before returning the storage reference
        for (target, ch) in info.name_mut().iter_mut().zip(name.chars()) {
            *target = ch
                .try_into()
                .map_err(|_| FileInfoCreationError::InvalidChar(ch))?;
        }
        info.name_mut()[name_length_ucs2 - 1] = NUL_16;
        Ok(info)
    }
}

/// Errors that can occur when creating a `FileProtocolInfo`
pub enum FileInfoCreationError {
    /// The provided buffer was too small to hold the `FileInfo`. You need at
    /// least the indicated buffer size (in bytes). Please remember that using
    /// a misaligned buffer will cause a decrease of usable storage capacity.
    InsufficientStorage(usize),

    /// The suggested file name contains invalid code points (not in UCS-2)
    InvalidChar(char),
}

/// Generic file information
///
/// The following rules apply when using this struct with `set_info()`:
///
/// - On directories, the file size is determined by the contents of the
///   directory and cannot be changed by setting `file_size`. This member is
///   ignored by `set_info()`.
/// - The `physical_size` is determined by the `file_size` and cannot be
///   changed. This member is ignored by `set_info()`.
/// - The `FileAttribute::DIRECTORY` bit cannot be changed. It must match the
///   file’s actual type.
/// - A value of zero in create_time, last_access, or modification_time causes
///   the fields to be ignored (and not updated).
/// - It is forbidden to change the name of a file to the name of another
///   existing file in the same directory.
/// - If a file is read-only, the only allowed change is to remove the read-only
///   attribute. Other changes must be carried out in a separate transaction.
#[repr(C)]
#[unsafe_guid("09576e92-6d3f-11d2-8e39-00a0c969723b")]
pub struct FileInfo {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: Time,
    last_access_time: Time,
    modification_time: Time,
    attribute: FileAttribute,
    name: [Char16],
}

impl FileInfo {
    /// Create a `FileInfo` structure
    ///
    /// The structure will be created in-place within the provided storage
    /// buffer. The buffer must be large enough to hold the data structure,
    /// including a null-terminated UCS-2 version of the `name` string.
    ///
    /// The buffer must be correctly aligned. You can query the required
    /// alignment using the `alignment()` method of the `Align` trait that this
    /// struct implements.
    #[allow(clippy::too_many_arguments)]
    pub fn new<'buf>(
        storage: &'buf mut [u8],
        file_size: u64,
        physical_size: u64,
        create_time: Time,
        last_access_time: Time,
        modification_time: Time,
        attribute: FileAttribute,
        file_name: &str,
    ) -> core::result::Result<&'buf mut Self, FileInfoCreationError> {
        let info = unsafe { Self::new_uninitialized(storage, file_name)? };
        info.size = mem::size_of_val(&info) as u64;
        info.file_size = file_size;
        info.physical_size = physical_size;
        info.create_time = create_time;
        info.last_access_time = last_access_time;
        info.modification_time = modification_time;
        info.attribute = attribute;
        Ok(info)
    }

    /// File size (number of bytes stored in the file)
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Physical space consumed by the file on the file system volume
    pub fn physical_size(&self) -> u64 {
        self.physical_size
    }

    /// Time when the file was created
    pub fn create_time(&self) -> &Time {
        &self.create_time
    }

    /// Time when the file was last accessed
    pub fn last_access_time(&self) -> &Time {
        &self.last_access_time
    }

    /// Time when the file's contents were last modified
    pub fn modification_time(&self) -> &Time {
        &self.modification_time
    }

    /// Attribute bits for the file
    pub fn attribute(&self) -> FileAttribute {
        self.attribute
    }

    /// Name of the file
    pub fn file_name(&self) -> &CStr16 {
        self.name_str()
    }
}

unsafe impl FileProtocolInfo for FileInfo {
    fn name(&self) -> &[Char16] {
        &self.name
    }
    fn name_mut(&mut self) -> &mut [Char16] {
        &mut self.name
    }
}

/// System volume information
///
/// May only be obtained on the root directory's file handle.
///
/// Please note that only the system volume's volume label may be set using
/// this information structure. Consider using `FileSystemVolumeLabel` instead.
#[repr(C)]
#[unsafe_guid("09576e93-6d3f-11d2-8e39-00a0c969723b")]
pub struct FileSystemInfo {
    size: u64,
    read_only: bool,
    volume_size: u64,
    free_space: u64,
    block_size: u32,
    name: [Char16],
}

impl FileSystemInfo {
    /// Create a `FileSystemInfo` structure
    ///
    /// The structure will be created in-place within the provided storage
    /// buffer. The buffer must be large enough to hold the data structure,
    /// including a null-terminated UCS-2 version of the `name` string.
    ///
    /// The buffer must be correctly aligned. You can query the required
    /// alignment using the `alignment()` method of the `Align` trait that this
    /// struct implements.
    #[allow(clippy::too_many_arguments)]
    pub fn new<'buf>(
        storage: &'buf mut [u8],
        read_only: bool,
        volume_size: u64,
        free_space: u64,
        block_size: u32,
        volume_label: &str,
    ) -> core::result::Result<&'buf mut Self, FileInfoCreationError> {
        let info = unsafe { Self::new_uninitialized(storage, volume_label)? };
        info.size = mem::size_of_val(&info) as u64;
        info.read_only = read_only;
        info.volume_size = volume_size;
        info.free_space = free_space;
        info.block_size = block_size;
        Ok(info)
    }

    /// Truth that the volume only supports read access
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Number of bytes managed by the file system
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// Number of available bytes for use by the file system
    pub fn free_space(&self) -> u64 {
        self.free_space
    }

    /// Nominal block size by which files are typically grown
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Volume label
    pub fn volume_label(&self) -> &CStr16 {
        self.name_str()
    }
}

unsafe impl FileProtocolInfo for FileSystemInfo {
    fn name(&self) -> &[Char16] {
        &self.name
    }
    fn name_mut(&mut self) -> &mut [Char16] {
        &mut self.name
    }
}

/// System volume label
///
/// May only be obtained on the root directory's file handle.
#[repr(C)]
#[unsafe_guid("db47d7d3-fe81-11d3-9a35-0090273fc14d")]
pub struct FileSystemVolumeLabel {
    name: [Char16],
}

impl FileSystemVolumeLabel {
    /// Create a `FileSystemVolumeLabel` structure
    ///
    /// The structure will be created in-place within the provided storage
    /// buffer. The buffer must be large enough to hold the data structure,
    /// including a null-terminated UCS-2 version of the `name` string.
    ///
    /// The buffer must be correctly aligned. You can query the required
    /// alignment using the `alignment()` method of the `Align` trait that this
    /// struct implements.
    pub fn new<'buf>(
        storage: &'buf mut [u8],
        volume_label: &str,
    ) -> core::result::Result<&'buf mut Self, FileInfoCreationError> {
        unsafe { Self::new_uninitialized(storage, volume_label) }
    }

    /// Volume label
    pub fn volume_label(&self) -> &CStr16 {
        self.name_str()
    }
}

unsafe impl FileProtocolInfo for FileSystemVolumeLabel {
    fn name(&self) -> &[Char16] {
        &self.name
    }
    fn name_mut(&mut self) -> &mut [Char16] {
        &mut self.name
    }
}

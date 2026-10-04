//! The NTFS volume collected from, read raw through `sootmark-disk`: a live
//! volume (`\\.\C:`, where Windows keeps files open that no API copies:
//! `$MFT`, the registry hives) or a disk image, the same code either way.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use disk::{identify, partitions, FileEntry, Filesystem, NtfsVolume, SECTOR_SIZE};

/// Bytes a raw device is read in: whole sectors, and enough to make
/// sequential reads cheap.
const BLOCK: usize = 1 << 20;
/// Where an NTFS boot sector keeps its sector size and sector count.
const BYTES_PER_SECTOR_AT: usize = 0x0b;
const TOTAL_SECTORS_AT: usize = 0x28;

/// Anything a volume can be read from.
pub trait Disk: Read + Seek {}
impl<T: Read + Seek> Disk for T {}

/// An open NTFS volume.
pub struct Volume {
    disk: Box<dyn Disk>,
    ntfs: NtfsVolume,
    /// What was opened, for the record.
    pub source: String,
}

impl Volume {
    /// A live volume, by device path (`\\.\C:`): read in whole sectors,
    /// as Windows requires of raw devices.
    ///
    /// # Errors
    /// When the device can't be opened (it needs administrator rights) or
    /// holds no NTFS.
    pub fn open_device(path: &str) -> io::Result<Self> {
        let mut device = Aligned::new(File::open(path)?);
        let length = ntfs_length(&mut device)?;
        device.length = length;
        let ntfs = NtfsVolume::open(&mut device, 0, length)?;
        Ok(Self {
            disk: Box::new(device),
            ntfs,
            source: path.to_owned(),
        })
    }

    /// The Windows volume of a raw disk image (or the largest NTFS one):
    /// for tests, and for collecting from an image the same way.
    ///
    /// # Errors
    /// When the image can't be read or holds no NTFS volume.
    pub fn open_image(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let (_, found) = partitions(&mut file, length)?;
        let mut best: Option<(bool, u64, NtfsVolume)> = None;
        for partition in found {
            if identify(&mut file, &partition)? != Filesystem::Ntfs {
                continue;
            }
            let ntfs = NtfsVolume::open(&mut file, partition.offset, partition.length)?;
            let windows = ntfs
                .files(&mut file)?
                .iter()
                .any(|f| f.path.len() == 1 && f.path[0].eq_ignore_ascii_case("Windows"));
            let rank = (windows, partition.length);
            if best.as_ref().map_or(true, |(w, l, _)| rank > (*w, *l)) {
                best = Some((windows, partition.length, ntfs));
            }
        }
        let (_, _, ntfs) = best.ok_or_else(|| invalid("no NTFS volume in the image"))?;
        Ok(Self {
            disk: Box::new(file),
            ntfs,
            source: path.display().to_string(),
        })
    }

    /// Every file and stream on the volume.
    ///
    /// # Errors
    /// When the MFT can't be read.
    pub fn files(&mut self) -> io::Result<Vec<FileEntry>> {
        self.ntfs.files(&mut self.disk)
    }

    /// Hand `file`'s content to `consume`.
    ///
    /// # Errors
    /// When it can't be read, or `consume` fails.
    pub fn read(
        &mut self,
        file: &FileEntry,
        consume: &mut dyn FnMut(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        self.ntfs.read(&mut self.disk, file, consume)
    }
}

/// An NTFS volume's size, from its boot sector: its sectors and the backup
/// boot sector after them.
fn ntfs_length(device: &mut impl Disk) -> io::Result<u64> {
    let mut boot = [0u8; SECTOR_SIZE as usize];
    device.seek(SeekFrom::Start(0))?;
    device.read_exact(&mut boot)?;
    let bytes_per_sector = u64::from(u16::from_le_bytes([
        boot[BYTES_PER_SECTOR_AT],
        boot[BYTES_PER_SECTOR_AT + 1],
    ]));
    let mut total = [0u8; 8];
    total.copy_from_slice(&boot[TOTAL_SECTORS_AT..TOTAL_SECTORS_AT + 8]);
    let sectors = u64::from_le_bytes(total);
    if &boot[3..7] != b"NTFS" || bytes_per_sector == 0 {
        return Err(invalid("not an NTFS volume"));
    }
    sectors
        .checked_add(1)
        .and_then(|s| s.checked_mul(bytes_per_sector))
        .ok_or_else(|| invalid("impossible NTFS volume size"))
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// Reads from a raw device in whole aligned blocks, whatever the caller
/// asks for, keeping the last block for the next read.
struct Aligned<R> {
    inner: R,
    position: u64,
    /// Device size, once known (for seeks from the end).
    length: u64,
    block_start: u64,
    block: Vec<u8>,
}

impl<R: Read + Seek> Aligned<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            position: 0,
            length: 0,
            block_start: 0,
            block: Vec::new(),
        }
    }

    /// Make the block hold `position`; false at the end of the device.
    fn fill(&mut self) -> io::Result<bool> {
        let held = self.block_start..self.block_start + self.block.len() as u64;
        if held.contains(&self.position) {
            return Ok(true);
        }
        let start = self.position - self.position % BLOCK as u64;
        self.inner.seek(SeekFrom::Start(start))?;
        self.block.resize(BLOCK, 0);
        let mut filled = 0;
        // A short read that ends off a sector boundary is the device's
        // end: reading on from there would be unaligned.
        while filled < BLOCK && filled % SECTOR_SIZE as usize == 0 {
            match self.inner.read(&mut self.block[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.block.truncate(filled);
        self.block_start = start;
        Ok(self.position < start + filled as u64)
    }
}

impl<R: Read + Seek> Read for Aligned<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || !self.fill()? {
            return Ok(0);
        }
        let at = (self.position - self.block_start) as usize;
        let n = buf.len().min(self.block.len() - at);
        buf[..n].copy_from_slice(&self.block[at..at + n]);
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for Aligned<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::Current(by) => self.position.checked_add_signed(by),
            SeekFrom::End(by) => self.length.checked_add_signed(by),
        };
        self.position = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A device that, like a Windows raw volume, refuses unaligned reads.
    struct Strict(Cursor<Vec<u8>>);

    impl Read for Strict {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let aligned = self.0.position() % 512 == 0 && buf.len() % 512 == 0;
            if !aligned {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unaligned"));
            }
            self.0.read(buf)
        }
    }

    impl Seek for Strict {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.0.seek(to)
        }
    }

    #[test]
    fn any_read_becomes_aligned_reads() {
        let data: Vec<u8> = (0..3 * BLOCK + 700).map(|i| (i % 251) as u8).collect();
        let mut device = Aligned::new(Strict(Cursor::new(data.clone())));
        for (at, len) in [(3, 10), (511, 2), (BLOCK - 5, 20), (3 * BLOCK + 600, 500)] {
            device.seek(SeekFrom::Start(at as u64)).unwrap();
            let mut buf = vec![0; len];
            let n = device.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], &data[at..at + n], "at {at}");
            assert!(n > 0);
        }
        let mut all = Vec::new();
        device.seek(SeekFrom::Start(0)).unwrap();
        device.read_to_end(&mut all).unwrap();
        assert_eq!(all, data);
    }
}

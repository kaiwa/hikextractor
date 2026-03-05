import mmap
import struct
import subprocess
import sys
import os
import os.path
import stat
import argparse
import dataclasses
from datetime import datetime
from typing import List, Optional, Tuple, Any

# Use the robust export pipeline from the CLI module
from hikextractor import export_file as _do_export_file

# --- Constants from Original Script ---
SIGNATURE = b"HIKVISION@HANGZHOU"
IDR_ENTRY_SIGNATURE = b"OFNI"
HIKBTREE_SIGNATURE = b"HIKBTREE"
BA_NAL = bytes.fromhex("00 00 01 BA")

# --- Data Model (No change needed) ---
@dataclasses.dataclass(frozen=True)
class MasterBlock:
    signature: bytes
    version: bytes
    capacity: int
    offset_system_logs: int
    size_system_logs: int
    offset_video_area: int
    size_data_block: int
    total_data_blocks: int
    offset_hibtree1: int
    size_hibtree1: int
    offset_hibtree2: int
    size_hibtree2: int
    time_system_init: datetime

@dataclasses.dataclass(frozen=True)
class HIKBTREEEntry:
    channel: int
    has_footage: bool
    recording: bool
    start_timestamp: Optional[datetime]
    end_timestamp: Optional[datetime]
    offset_datablock: int

# --- Helper functions (No change needed) ---
def to_uint8(buff: bytes, offset: int) -> int:
    return struct.unpack("B", buff[offset : offset + 1])[0]

def to_uint32(buff: bytes, offset: int) -> int:
    return struct.unpack("<I", buff[offset : offset + 4])[0]

def to_uint64(buff: bytes, offset: int) -> int:
    return struct.unpack("<Q", buff[offset : offset + 8])[0]

def to_datetime(buff: bytes, offset: int) -> datetime:
    # Use utcfromtimestamp for compatibility with original code
    return datetime.utcfromtimestamp(to_uint32(buff, offset))

def find_in_bytes(buff: bytes, what: bytes, start, size=1024 * 1024):
    result = buff[start : start + size].find(what)
    if result < 0:
        return result
    return result + start

def get_file_size(fp):
    return fp.seek(0, os.SEEK_END)


class _SeekReader:
    """
    Slice-addressable wrapper around a file/device that uses os.pread()
    instead of mmap.  Avoids SIGBUS on block devices with bad sectors or
    sparse regions — pread raises OSError instead of crashing the process.
    """

    def __init__(self, path: str):
        self._fd = os.open(path, os.O_RDONLY)
        self._size = os.lseek(self._fd, 0, os.SEEK_END)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, _ = key.indices(self._size)
            length = max(0, stop - start)
            return os.pread(self._fd, length, start) if length else b""
        if isinstance(key, int):
            if key < 0:
                key += self._size
            data = os.pread(self._fd, 1, key)
            return data[0] if data else 0
        raise TypeError(f"Unsupported index type: {type(key)}")

    def __len__(self):
        return self._size

    def close(self):
        os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# --- Parsing functions (No change needed) ---
def parse_master_block(mappedfile) -> MasterBlock:
    # ... (Keep the exact code for parse_master_block)
    master = mappedfile[0x200:0x360]
    signature = bytes(master[0x10:0x22])
    if signature != SIGNATURE:
        raise Exception("Wrong master block signature")
    version = bytes(master[0x30:0x3E])
    capacity = to_uint64(master, 0x48)
    offset_system_logs = to_uint64(master, 0x60)
    size_system_logs = to_uint64(master, 0x68)
    offset_video_area = to_uint64(master, 0x78)
    size_data_block = to_uint64(master, 0x88)
    total_data_blocks = to_uint32(master, 0x90)
    offset_hibtree1 = to_uint64(master, 0x98)
    size_hibtree1 = to_uint32(master, 0xA0)
    offset_hibtree2 = to_uint64(master, 0xA8)
    size_hibtree2 = to_uint32(master, 0xB0)
    time_system_init = to_datetime(master, 0xF0)
    return MasterBlock(
        signature=signature,
        capacity=capacity,
        version=version,
        offset_system_logs=offset_system_logs,
        size_system_logs=size_system_logs,
        offset_video_area=offset_video_area,
        size_data_block=size_data_block,
        total_data_blocks=total_data_blocks,
        offset_hibtree1=offset_hibtree1,
        size_hibtree1=size_hibtree1,
        offset_hibtree2=offset_hibtree2,
        size_hibtree2=size_hibtree2,
        time_system_init=time_system_init,
    )

def parse_hbt_entry(data, offset) -> Optional[HIKBTREEEntry]:
    # ... (Keep the exact code for parse_hbt_entry)
    has_footage = to_uint64(data, offset + 0x8) == 0
    channel = to_uint8(data, offset + 0x11)
    dt1 = to_uint32(data, offset + 0x18)
    offset_datablock = to_uint64(data, offset + 0x20)
    recording = False
    start_timestamp = None
    end_timestamp = None
    if has_footage:
        if dt1 == 0x7FFFFFFF:
            recording = True
        else:
            start_timestamp = to_datetime(data, offset + 0x18)
            end_timestamp = to_datetime(data, offset + 0x1C)
    else:
        return None
    return HIKBTREEEntry(
        channel=channel,
        has_footage=has_footage,
        recording=recording,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        offset_datablock=offset_datablock,
    )


def parse_hbtree(data, masterblock: MasterBlock) -> List[HIKBTREEEntry]:
    # ... (Keep the exact code for parse_hbtree)
    offset = masterblock.offset_hibtree1
    signature = bytes(data[offset + 0x10 : offset + 0x18])
    if signature != HIKBTREE_SIGNATURE:
        raise Exception("Wrong HIKBTREE Signature")
    offset_page = to_uint64(data, offset + 0x58)

    entries = []
    safe_count = 0

    # parse pages:
    while True:
        entry_count = to_uint32(data, offset_page + 0x10)
        next_page = to_uint64(data, offset_page + 0x20)
        first_entry = offset_page + 0x60
        for i in range(entry_count):
            entry = parse_hbt_entry(data, first_entry + i * 48)
            if entry is not None:
                entries.append(entry)
        if next_page == 0xFFFFFFFFFFFFFFFF:
            break
        offset_page = next_page
        safe_count += 1
        if safe_count > 1000: # Increased safe_count limit for large drives
            print("Warning: HIKBTREE page limit reached.")
            break

    return entries


# --- Export functions (Re-used, slightly modified) ---
def export_footage_from_block(datablock, outfile):
    start_offset = find_in_bytes(datablock, BA_NAL, 0, 4096)
    if start_offset < 0:
        return

    # Use a chunked reading approach to export the stream
    chunk_size = 120 * 1024 # 120KB
    current_offset = start_offset
    
    while True:
        # Search for the next BA_NAL block within a defined window
        search_area_start = current_offset + len(BA_NAL)
        end_offset = find_in_bytes(datablock, BA_NAL, search_area_start, chunk_size)
        
        if end_offset < 0:
            # Reached end of block or last chunk
            try:
                outfile.write(datablock[current_offset:])
            except:
                pass
            return

        try:
            outfile.write(datablock[current_offset:end_offset])
        except:
            return
        
        current_offset = end_offset

def rename_file_if_exists(filename: str) -> str:
    count = 1
    new_filename = filename
    while os.path.exists(new_filename):
        base, ext = os.path.splitext(filename)
        new_filename = f"{base}_{count}{ext}"
        count += 1
    return new_filename


def export_file_with_audio(datablock: bytes, filename: str):
    """Exports video with audio by extracting and processing G.711 audio from Hikvision MPEG-PS stream."""
    import tempfile
    import struct

    # Step 1: Save MPEG-PS stream to temp file
    temp_mpeg = tempfile.NamedTemporaryFile(suffix='.mpg', delete=False)
    temp_audio_raw = tempfile.NamedTemporaryFile(suffix='.pcm', delete=False)

    try:
        # Write MPEG-PS data to temp file
        export_footage_from_block(datablock, temp_mpeg)
        temp_mpeg.close()

        # Step 2: Manually extract G.711 audio payload from MPEG-PS packets
        with open(temp_mpeg.name, 'rb') as f:
            ps_data = f.read()

        audio_payloads = []
        pos = 0
        while pos < len(ps_data) - 10:
            if ps_data[pos:pos+4] == b'\x00\x00\x01\xC0':  # Audio stream 0
                packet_length = struct.unpack('>H', ps_data[pos+4:pos+6])[0]
                if pos + 8 < len(ps_data):
                    pes_header_len = ps_data[pos+8]
                    payload_start = pos + 9 + pes_header_len
                    payload_end = pos + 6 + packet_length

                    if payload_end <= len(ps_data) and payload_start < payload_end:
                        audio_payloads.append(ps_data[payload_start:payload_end])
                pos += 4
            else:
                pos += 1

        # Step 4: Write raw audio to file
        with open(temp_audio_raw.name, 'wb') as f:
            for payload in audio_payloads:
                f.write(payload)

        # Step 3: Remux MPEG-PS with extracted G.711 audio
        successful_codec = None
        for audio_codec in ['mulaw', 'alaw']:
            result = subprocess.run([
                "ffmpeg",
                "-i", temp_mpeg.name,
                "-f", audio_codec, "-ar", "8000", "-ac", "1", "-i", temp_audio_raw.name,
                "-c:v", "copy",
                "-c:a", "aac", "-b:a", "64k",
                "-shortest",
                "-loglevel", "error",
                "-y", filename
            ], capture_output=True)

            # Check if audio stream is in output
            check = subprocess.run([
                "ffprobe", "-v", "error", "-select_streams", "a", "-show_entries", "stream=codec_type",
                "-of", "default=noprint_wrappers=1:nokey=1", filename
            ], capture_output=True, text=True)

            has_audio = 'audio' in check.stdout

            if os.path.exists(filename) and os.path.getsize(filename) > 0 and has_audio:
                successful_codec = audio_codec
                print(f"Audio decoded successfully as G.711 {audio_codec} and muxed with video")
                break
            else:
                if not has_audio and result.stderr:
                    print(f"  {audio_codec} failed: {result.stderr.decode('utf-8', errors='ignore')[:200]}")
                if os.path.exists(filename):
                    os.remove(filename)

        # Check result
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            file_size = os.path.getsize(filename) / (1024 * 1024)
            print(f"Successfully created MP4 with audio: {os.path.basename(filename)} ({file_size:.2f} MB)")
            return True
        else:
            print(f"Failed to create MP4 with audio. stderr: {result.stderr.decode('utf-8', errors='ignore')}")
            return False

    finally:
        # Clean up temp files
        for temp_file in [temp_mpeg, temp_audio_raw]:
            try:
                os.unlink(temp_file.name)
            except:
                pass


def export_file(datablock: bytes, filename: str, raw: bool):
    """Handles piping raw data to FFmpeg or saving raw stream."""
    if not raw:
        # Check for FFmpeg first
        try:
            subprocess.run(["ffmpeg", "-h"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("FFmpeg not found or not working. Exporting as raw H.264 instead.")
            raw = True

    if not raw:
        # Try to export with audio first
        print("Attempting to export with audio (G.711 decoding)...")
        if export_file_with_audio(datablock, filename):
            return

        # If audio export fails, fall back to video-only
        print("Audio export failed, falling back to video-only MP4...")
        process = subprocess.Popen(
            [
                "ffmpeg",
                "-err_detect", "ignore_err",
                "-i", "-",
                "-c:v", "copy",
                "-an",  # Skip audio
                "-bsf:v", "filter_units=pass_types=1-5",
                "-aspect", "4/3",
                "-loglevel", "warning",
                "-stats",
                "-y",
                filename,
            ],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        export_footage_from_block(datablock, process.stdin)
        stdout, stderr = process.communicate()

        if not os.path.exists(filename) or os.path.getsize(filename) == 0:
            stderr_output = stderr.decode('utf-8', errors='ignore')
            print(f"Warning: FFmpeg failed to create MP4. stderr: {stderr_output}")
            print("Falling back to raw H.264 export...")

            if os.path.exists(filename):
                os.remove(filename)

            raw_filename = filename.rsplit('.', 1)[0] + '.h264'
            with open(raw_filename, 'wb') as out:
                export_footage_from_block(datablock, out)
            print(f"Exported as raw H.264: {raw_filename}")
        else:
            file_size = os.path.getsize(filename) / (1024 * 1024)
            print(f"Successfully created video-only MP4: {os.path.basename(filename)} ({file_size:.2f} MB)")
    else:
        # Raw H.264 export
        with open(filename,'wb') as out:
            export_footage_from_block(datablock, out)
            

# --- Main Logic Class for GUI Worker ---
class HikvisionParser:
    """A wrapper class for the core forensic functions."""
    
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.master_block: Optional[MasterBlock] = None
        self.entry_list: List[HIKBTREEEntry] = []
        
    def parse_metadata(self) -> Tuple[MasterBlock, List[HIKBTREEEntry]]:
        """Parses the MasterBlock and HIKBTREE from the disk image or block device."""
        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Input not found: {self.source_path}")
        st = os.stat(self.source_path)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISBLK(st.st_mode)):
            raise ValueError(f"Input must be a regular file or block device: {self.source_path}")

        is_device = stat.S_ISBLK(os.stat(self.source_path).st_mode)

        if is_device:
            # Use pread-based reader to avoid SIGBUS on block devices
            with _SeekReader(self.source_path) as reader:
                master = parse_master_block(reader)
                entrylist = parse_hbtree(reader, master)
        else:
            with open(self.source_path, "rb") as input_image:
                size = get_file_size(input_image)
                with mmap.mmap(
                    input_image.fileno(), size, access=mmap.ACCESS_READ
                ) as mmapped_file:
                    master = parse_master_block(mmapped_file)
                    entrylist = parse_hbtree(mmapped_file, master)

        # Sort entries: Recording first, then by timestamp, then by channel
        def sortkey(x):
            if x.recording:
                return f"00REC-{x.channel:02d}"
            return f"{x.start_timestamp:%Y%m%d%H%M}-{x.channel:02d}"
        
        entrylist = sorted(entrylist, key=sortkey)
        
        self.master_block = master
        self.entry_list = entrylist
        
        return master, entrylist

    def export_video_block(self, entry: HIKBTREEEntry, dest_folder: str, raw: bool):
        """Exports a single video block based on a HIKBTREE entry."""
        if not self.master_block:
            raise Exception("Metadata not parsed. Run parse_metadata first.")

        ext = "h264" if raw else "mp4"
        if entry.recording:
            filename = f"CH-{entry.channel:02d}__RECORDING.{ext}"
        else:
            start = entry.start_timestamp
            end = entry.end_timestamp
            filename = f"CH-{entry.channel:02d}__{start:%Y-%m-%d-%H-%M}__{end:%Y-%m-%d-%H-%M}.{ext}"

        full_path = rename_file_if_exists(os.path.join(dest_folder, filename))

        block_size = self.master_block.size_data_block
        start_offset = entry.offset_datablock
        end_offset = start_offset + block_size

        st = os.stat(self.source_path)
        if stat.S_ISBLK(st.st_mode):
            # Read in 4 MB chunks from block device
            CHUNK = 4 * 1024 * 1024
            fd = os.open(self.source_path, os.O_RDONLY)
            try:
                parts = []
                done = 0
                while done < block_size:
                    to_read = min(CHUNK, block_size - done)
                    chunk = os.pread(fd, to_read, start_offset + done)
                    if not chunk:
                        break
                    parts.append(chunk)
                    done += len(chunk)
                datablock = b"".join(parts)
            finally:
                os.close(fd)
        else:
            with open(self.source_path, "rb") as input_image:
                size = get_file_size(input_image)
                with mmap.mmap(
                    input_image.fileno(), size, access=mmap.ACCESS_READ
                ) as mmapped_file:
                    datablock = bytes(mmapped_file[start_offset:end_offset])

        _do_export_file(datablock, full_path, raw)
        return full_path
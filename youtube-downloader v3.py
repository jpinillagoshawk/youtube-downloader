import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import yt_dlp
import os
import re
import subprocess
import sys
import platform
from threading import Thread
from datetime import datetime

# Detect operating system
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
FFMPEG_EXE = 'ffmpeg.exe' if IS_WINDOWS else 'ffmpeg'

def setup_ffmpeg_path():
    """Add bundled ffmpeg to PATH so yt-dlp can find it."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ffmpeg_dir = os.path.join(script_dir, 'ffmpeg', 'bin')
    if os.path.exists(ffmpeg_dir):
        # Prepend ffmpeg directory to PATH
        os.environ['PATH'] = ffmpeg_dir + os.pathsep + os.environ.get('PATH', '')
        return True
    return False

# Setup ffmpeg path at module load time
setup_ffmpeg_path()

def get_app_path():
    """Get the application path, handling PyInstaller bundled apps."""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def get_downloads_folder():
    """Get a sensible downloads folder location."""
    if getattr(sys, 'frozen', False):
        # When running as app, use user's Downloads folder
        if IS_MACOS:
            return os.path.expanduser('~/Downloads/YouTubeMP3')
        elif IS_WINDOWS:
            return os.path.join(os.path.expanduser('~'), 'Downloads', 'YouTubeMP3')
    # When running as script, use local downloads folder
    return os.path.join(get_app_path(), 'downloads')

class LogWindow:
    def __init__(self, parent, logs):
        self.parent_logs = logs
        self.window = tk.Toplevel(parent)
        self.window.title("Download Logs")
        self.window.geometry("800x600")
        
        # Create text widget with scrollbar
        self.text_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, width=80, height=30)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Insert logs
        self.update_logs()
        
        # Auto-refresh button
        self.auto_refresh = tk.BooleanVar(value=False)
        self.refresh_checkbox = ttk.Checkbutton(
            self.window, 
            text="Auto-refresh (every 5s)", 
            variable=self.auto_refresh,
            command=self.toggle_auto_refresh
        )
        self.refresh_checkbox.pack(pady=5)
        
        # Manual refresh button
        self.refresh_btn = ttk.Button(
            self.window, 
            text="Refresh Logs",
            command=self.update_logs
        )
        self.refresh_btn.pack(pady=5)
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def toggle_auto_refresh(self):
        if self.auto_refresh.get():
            self.auto_refresh_logs()
            
    def auto_refresh_logs(self):
        if self.auto_refresh.get():
            self.update_logs()
            self.window.after(5000, self.auto_refresh_logs)
            
    def update_logs(self):
        self.text_area.configure(state='normal')
        self.text_area.delete(1.0, tk.END)
        for log in self.parent_logs:
            self.text_area.insert(tk.END, f"{log}\n")
        self.text_area.configure(state='disabled')
        self.text_area.see(tk.END)  # Scroll to bottom
        
    def on_closing(self):
        self.auto_refresh.set(False)  # Stop auto-refresh
        self.window.destroy()

class YouTubeDownloader:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube to MP3 Downloader")
        self.root.geometry("600x400")  # Slightly increased height for new control
        self.root.resizable(False, False)
        
        # Initialize logs
        self.logs = []
        self._log_window = None
        self.pulsing_active = False  # Flag to control progress bar pulsing
        self.add_log("Application started")
        
        # Check if FFmpeg is in PATH
        self.ffmpeg_in_path = self.check_ffmpeg_in_path()
        if self.ffmpeg_in_path:
            self.add_log("FFmpeg found in system PATH")
        else:
            # Check relative path (bundled ffmpeg)
            relative_path = os.path.join(get_app_path(), 'ffmpeg', 'bin')
            if os.path.exists(os.path.join(relative_path, FFMPEG_EXE)):
                self.add_log(f"FFmpeg found in relative path: {relative_path}")
            else:
                self.add_log("FFmpeg not found in PATH or relative path. Please specify the path manually.")
        
        # Configure style
        style = ttk.Style()
        style.configure("TButton", padding=5)
        style.configure("TLabel", padding=5)
        style.configure("TEntry", padding=5)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL Input
        url_label = ttk.Label(main_frame, text="Enter YouTube URLs (one per line):")
        url_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Create a frame for the text widget and scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Create text widget with scrollbar
        self.url_text = tk.Text(text_frame, height=3, width=50, wrap=tk.WORD)
        self.url_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.url_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text widget to use scrollbar
        self.url_text.configure(yscrollcommand=scrollbar.set)
        
        # FFmpeg path input
        ffmpeg_frame = ttk.Frame(main_frame)
        ffmpeg_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ffmpeg_label = ttk.Label(ffmpeg_frame, text="FFmpeg path (optional):")
        ffmpeg_label.pack(side=tk.LEFT, padx=5)
        
        self.ffmpeg_path = tk.StringVar()
        ffmpeg_entry = ttk.Entry(ffmpeg_frame, textvariable=self.ffmpeg_path, width=40)
        ffmpeg_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(ffmpeg_frame, text="Browse", command=self.browse_ffmpeg)
        browse_button.pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=20)
        
        # Download Button
        self.download_button = ttk.Button(button_frame, text="Download MP3", command=self.start_download)
        self.download_button.pack(side=tk.LEFT, padx=5)
        
        # View Logs Button
        self.logs_button = ttk.Button(button_frame, text="View Logs", command=self.show_logs)
        self.logs_button.pack(side=tk.LEFT, padx=5)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status Label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        
        # Bind closing event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def add_log(self, message):
        """Add a timestamped log entry."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        
        # Update log window if it's open
        if self._log_window is not None:
            try:
                if self._log_window.window.winfo_exists():
                    self._log_window.update_logs()
            except tk.TclError:
                self._log_window = None
    
    def show_logs(self):
        """Show the logs window."""
        try:
            if self._log_window is None or not self._log_window.window.winfo_exists():
                self._log_window = LogWindow(self.root, self.logs)
            else:
                self._log_window.window.lift()  # Bring window to front
                self._log_window.update_logs()
        except (tk.TclError, AttributeError):
            self._log_window = LogWindow(self.root, self.logs)
    
    def validate_url(self, url):
        """Validate YouTube URL format."""
        youtube_regex = r'^(https?://)?(www\.)?(youtube\.com/watch\?v=|youtu\.be/)[A-Za-z0-9_-]+.*$'
        return bool(re.match(youtube_regex, url))
    
    def start_download(self):
        """Start the download process in a separate thread for each valid URL."""
        # Get all URLs from text widget
        urls_text = self.url_text.get("1.0", tk.END).strip()
        if not urls_text:
            self.add_log("Error: No URLs provided")
            messagebox.showerror("Error", "Please enter at least one YouTube URL")
            return
        
        # Split text into URLs and filter out empty lines
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        # Filter valid URLs
        valid_urls = [url for url in urls if self.validate_url(url)]
        
        if not valid_urls:
            self.add_log("Error: No valid YouTube URLs found")
            messagebox.showerror("Error", "No valid YouTube URLs found")
            return
        
        # Log number of valid URLs found
        self.add_log(f"Found {len(valid_urls)} valid URLs out of {len(urls)} total")
        
        # Disable download button
        self.download_button.state(['disabled'])
        self.status_var.set("Starting downloads...")
        self.progress_var.set(0)
        
        # Start download thread
        Thread(target=self.process_urls, args=(valid_urls,), daemon=True).start()
    
    def process_urls(self, urls):
        """Process multiple URLs sequentially."""
        total_urls = len(urls)
        successful_downloads = []
        failed_downloads = []

        for index, url in enumerate(urls, 1):
            try:
                # Update main window status with current video number
                status_text = f"Processing video {index}/{total_urls}"
                self.root.after(0, lambda: self.status_var.set(status_text))
                self.add_log(f"Starting download {index}/{total_urls} for URL: {url}")
                
                # Download the video
                self.download_mp3(url, index, total_urls)
                successful_downloads.append(url)
                
            except Exception as e:
                error_message = str(e)
                self.add_log(f"Error processing URL {url}: {error_message}")
                failed_downloads.append((url, error_message))
        
        # Re-enable download button
        self.root.after(0, lambda: self.download_button.state(['!disabled']))
        # Show completion status with count of successful downloads
        completion_msg = f"All downloads complete. {len(successful_downloads)} of {total_urls} files successfully processed."
        self.root.after(0, lambda: self.status_var.set(completion_msg))
        self.add_log(completion_msg)
        
        # Reset progress bar
        self.root.after(0, lambda: self.progress_var.set(0))
        
        # Show summary if there was more than one URL
        if total_urls > 1:
            summary = f"Downloads completed:\n\n"
            summary += f"✓ Successful: {len(successful_downloads)}\n"
            summary += f"✗ Failed: {len(failed_downloads)}\n\n"
            
            if failed_downloads:
                summary += "Failed downloads:\n"
                for url, error in failed_downloads:
                    summary += f"• {url}\n   Error: {error}\n"
            
            self.root.after(0, lambda: messagebox.showinfo("Download Summary", summary))
        elif failed_downloads:
            # If single download failed, show error message
            self.root.after(0, lambda: messagebox.showerror("Error", f"Download failed: {failed_downloads[0][1]}"))
    
    def download_mp3(self, url, current_index=None, total_urls=None):
        """Download and convert YouTube video to MP3."""
        try:
            # Create downloads folder if it doesn't exist
            downloads_folder = get_downloads_folder()
            if not os.path.exists(downloads_folder):
                os.makedirs(downloads_folder)
                self.add_log(f"Created downloads directory: {downloads_folder}")

            # Configure yt-dlp options
            ydl_opts = {
                'format': 'bestaudio/best',
                'outtmpl': os.path.join(downloads_folder, '%(title)s.%(ext)s'),
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': '192',
                }],
                'progress_hooks': [
                    lambda d: self.download_progress_hook(d, current_index, total_urls)
                ],
                'logger': self.create_logger(),
                'verbose': True,  # Add verbose output for better debugging
                'no_check_certificate': True,  # Skip certificate validation
                'noplaylist': True,  # Only download single video, not playlist
            }
            
            # Add FFmpeg path if specified by user
            if self.ffmpeg_path.get():
                ydl_opts['ffmpeg_location'] = self.ffmpeg_path.get()
                self.add_log(f"Using custom FFmpeg path: {self.ffmpeg_path.get()}")
            # If not in PATH, use relative path if available (bundled ffmpeg)
            elif not self.ffmpeg_in_path:
                relative_path = os.path.join(get_app_path(), 'ffmpeg', 'bin')
                if os.path.exists(os.path.join(relative_path, FFMPEG_EXE)):
                    ydl_opts['ffmpeg_location'] = relative_path
                    self.add_log(f"Using FFmpeg from relative path: {relative_path}")

            # Update status based on whether this is part of multiple downloads
            if current_index and total_urls:
                status = f"Video {current_index}/{total_urls} - Fetching information..."
            else:
                status = "Fetching video information..."
            
            self.root.after(0, lambda: self.status_var.set(status))
            self.add_log("Fetching video information...")

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                # Get video info first
                info = ydl.extract_info(url, download=False)
                video_title = info.get('title', 'video')
                self.add_log(f"Found video: {video_title}")
                
                # Update status with download start
                if current_index and total_urls:
                    status = f"Video {current_index}/{total_urls} - Downloading {video_title}..."
                else:
                    status = f"Downloading {video_title}..."
                self.root.after(0, lambda: self.status_var.set(status))
                
                # Download the video
                self.add_log("Starting audio download...")
                ydl.download([url])
                
                self.add_log(f"Download completed: {video_title}.mp3")
                
                # Show success message only for single downloads
                if not (current_index and total_urls):
                    self.root.after(0, lambda: messagebox.showinfo("Success", 
                        f"Download complete!\nFile saved as: {video_title}.mp3"))
                
        except Exception as e:
            error_message = str(e)
            self.add_log(f"Error during download: {error_message}")
            # Show error message only for single downloads
            if not (current_index and total_urls):
                self.root.after(0, lambda: messagebox.showerror("Error", error_message))
            raise  # Re-raise the exception to be caught by process_urls
            
        finally:
            if not (current_index and total_urls):
                # Reset UI only if it's a single download
                self.root.after(0, lambda: self.download_button.state(['!disabled']))
                self.root.after(0, lambda: self.status_var.set("Ready"))
            self.root.after(0, lambda: self.progress_var.set(0))
    
    def download_progress_hook(self, d, current_index=None, total_urls=None):
        """Progress hook for yt-dlp."""
        try:
            if d['status'] == 'downloading':
                # Add logging to debug the progress data - uncomment for debugging
                #if 'downloaded_bytes' in d:
                #    self.add_log(f"Debug: Downloaded bytes: {d['downloaded_bytes']}")
                #if 'total_bytes' in d:
                #    self.add_log(f"Debug: Total bytes: {d['total_bytes']}")
                #if 'total_bytes_estimate' in d:
                #    self.add_log(f"Debug: Total bytes estimate: {d['total_bytes_estimate']}")
                
                # Calculate percentage
                total_bytes = d.get('total_bytes', 0) or d.get('total_bytes_estimate', 0)
                downloaded_bytes = d.get('downloaded_bytes', 0)
                
                # If we have a valid download size
                if total_bytes > 0 and downloaded_bytes > 0:
                    # Stop pulsing if it was active
                    if self.pulsing_active:
                        self.pulsing_active = False
                    
                    percentage = min(100, (downloaded_bytes / total_bytes) * 100)
                    
                    # Update progress bar - ensure this is on the main thread
                    def update_progress():
                        self.progress_var.set(percentage)
                        
                        # Format speed string for status
                        speed = d.get('speed', 0)
                        if speed:
                            speed_mb = speed / 1024 / 1024  # Convert to MB/s
                            if current_index and total_urls:
                                status = f"Video {current_index}/{total_urls} - Downloading: {percentage:.1f}% ({speed_mb:.1f} MB/s)"
                            else:
                                status = f"Downloading: {percentage:.1f}% ({speed_mb:.1f} MB/s)"
                        else:
                            if current_index and total_urls:
                                status = f"Video {current_index}/{total_urls} - Downloading: {percentage:.1f}%"
                            else:
                                status = f"Downloading: {percentage:.1f}%"
                        
                        self.status_var.set(status)
                    
                    # Schedule the update on the main thread
                    self.root.after(0, update_progress)
                    
                    # Log progress at 25% intervals
                    if percentage % 25 < 1 and percentage > 0:
                        self.add_log(f"Download progress: {percentage:.1f}%")
                
                # If we don't have size info but have a progress string, use that
                elif 'downloaded_bytes' in d and d['downloaded_bytes'] > 0:
                    # When total size is unknown, at least show that something is happening
                    status = f"Downloading: {d['downloaded_bytes'] / (1024*1024):.1f} MB downloaded"
                    self.root.after(0, lambda s=status: self.status_var.set(s))
                    
                    # Start pulsing if not already pulsing
                    if not self.pulsing_active:
                        self.pulsing_active = True
                        self.root.after(0, self.pulse_progress_bar)
            
            elif d['status'] == 'finished':
                # Stop pulsing if it was active
                self.pulsing_active = False
                
                self.add_log("Download finished, converting to MP3...")
                # Set progress to 100% for the download phase
                self.root.after(0, lambda: self.progress_var.set(100))
                
                if current_index and total_urls:
                    status = f"Video {current_index}/{total_urls} - Converting to MP3..."
                else:
                    status = "Converting to MP3..."
                self.root.after(0, lambda: self.status_var.set(status))
            
        except Exception as e:
            self.add_log(f"Error updating progress: {str(e)}")
    
    def pulse_progress_bar(self):
        """Create a pulsing effect for the progress bar when total size is unknown."""
        if not self.pulsing_active:
            return
            
        current = self.progress_var.get()
        if current >= 100:
            self.progress_var.set(0)
        else:
            self.progress_var.set(current + 2)  # Increment by small amount
        
        # Continue pulsing if still active
        if self.pulsing_active:
            self.root.after(100, self.pulse_progress_bar)
    
    def create_logger(self):
        """Create a logger for yt-dlp."""
        outer_self = self
        class Logger:
            def debug(self, msg):
                # Uncomment the following line if you want to see debug messages
                # outer_self.add_log(f"Debug: {msg}")
                pass
            
            def warning(self, msg):
                outer_self.add_log(f"Warning: {msg}")
            
            def error(self, msg):
                outer_self.add_log(f"Error: {msg}")
        return Logger()
    
    def save_logs(self):
        """Save logs to a file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"Logs_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for log in self.logs:
                    f.write(f"{log}\n")
            self.add_log(f"Logs saved to: {filename}")
        except Exception as e:
            self.add_log(f"Error saving logs: {str(e)}")
    
    def on_closing(self):
        """Handle application closing."""
        self.add_log("Application shutting down")
        self.save_logs()
        self.root.destroy()
    
    def browse_ffmpeg(self):
        """Open file dialog to select FFmpeg executable"""
        if IS_WINDOWS:
            filetypes = [("Executable files", "*.exe"), ("All files", "*.*")]
        else:
            filetypes = [("All files", "*")]
        ffmpeg_file = tk.filedialog.askopenfilename(
            title="Select FFmpeg executable",
            filetypes=filetypes
        )
        if ffmpeg_file:
            # Get the directory containing ffmpeg.exe
            ffmpeg_dir = os.path.dirname(ffmpeg_file)
            self.ffmpeg_path.set(ffmpeg_dir)
            self.add_log(f"FFmpeg path set to: {ffmpeg_dir}")

    def check_ffmpeg_in_path(self):
        """Check if FFmpeg is available in the system PATH"""
        try:
            # Run a simple ffmpeg command to check if it's available
            subprocess.run(['ffmpeg', '-version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            return True
        except FileNotFoundError:
            return False

def main():
    root = tk.Tk()
    app = YouTubeDownloader(root)
    root.mainloop()

if __name__ == "__main__":
    main()
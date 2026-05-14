import os
import cv2
from PIL import Image
import argparse
from pathlib import Path

def extract_frames(video_path, output_dir):
    """Extract frames from a video into high-quality WebP format using OpenCV and Pillow."""
    
    if not os.path.exists(video_path):
        print(f"Error: Video file '{video_path}' not found.")
        return

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Opening video '{video_path}'...")
    cap = cv2.VideoCapture(video_path)
    
    if not cap.isOpened():
        print("Error: Could not open the video file.")
        return

    frame_count = 0
    print("Extracting frames as high-quality WebP...")
    
    while True:
        ret, frame = cap.read()
        if not ret:
            break
            
        # Convert BGR (OpenCV) to RGB (Pillow)
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(frame_rgb)
        
        # Save as WebP with high quality
        out_file = out_path / f"frame-{frame_count + 1:03d}.webp"
        pil_img.save(out_file, "WEBP", quality=90, method=6)
        
        frame_count += 1
        if frame_count % 20 == 0:
            print(f"Extracted {frame_count} frames...")
            
    cap.release()
    print("\nExtraction complete!")
    print(f"Generated {frame_count} frames.")
    print(f"Please ensure 'const TOTAL_FRAMES = {frame_count};' in your main.js matches this count.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract high-quality WebP frames using OpenCV.")
    parser.add_argument("video_path", help="Path to your video file")
    parser.add_argument("--out", default="safemailx-website/public/images", help="Output directory")
    
    args = parser.parse_args()
    extract_frames(args.video_path, args.out)

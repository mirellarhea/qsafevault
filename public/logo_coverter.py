from PIL import Image
import os

file_name = 'logo.png'  
current_dir = os.path.dirname(os.path.abspath(__file__))
png_path = os.path.join(current_dir, file_name)
ico_path = os.path.join(current_dir, os.path.splitext(file_name)[0] + '.ico')

with Image.open(png_path) as img:

    img.save(ico_path, format='ICO', sizes=[(256, 256)])

print(f"Converted '{file_name}' to ICO format at '{ico_path}'")

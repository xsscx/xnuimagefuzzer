import OpenEXR
import Imath
import numpy as np
import matplotlib.pyplot as plt
import logging
from skimage.transform import resize

def analyze_subsampling_and_render_image(exr_path):
	logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
	logging.info(f"Analyzing EXR file: {exr_path}")
	
	try:
		exr_file = OpenEXR.InputFile(exr_path)
		header = exr_file.header()
		
		dw = header['dataWindow']
		size = (dw.max.x - dw.min.x + 1, dw.max.y - dw.min.y + 1)
		total_pixels = size[0] * size[1]
		
		channels = header['channels']
		channel_keys = list(channels.keys())
		logging.info(f"EXR file size: {size[0]}x{size[1]}, Total Pixels: {total_pixels}")
		logging.info(f"Header Info: {header}")
		logging.info(f"Channel Keys: {channel_keys}")
		
		pt = Imath.PixelType(Imath.PixelType.HALF)
		images = {}
		channel_sizes = {}
		
		for channel_name, channel_info in channels.items():
			x_sampling, y_sampling = channel_info.xSampling, channel_info.ySampling
			expected_width = size[0] // x_sampling
			expected_height = size[1] // y_sampling
			expected_size = expected_width * expected_height
			logging.info(f"Channel '{channel_name}' subsampling: {x_sampling}x{y_sampling}, Expected size: {expected_size}")
			
			# Load the channel data to compute actual size
			buffer = exr_file.channel(channel_name, pt)
			data = np.frombuffer(buffer, dtype=np.float16)
			actual_size = data.size
			channel_sizes[channel_name] = (expected_size, actual_size)
			
			logging.info(f"Channel '{channel_name}' actual size: {actual_size}")
			
			if actual_size != expected_size:
				logging.error(f"Channel '{channel_name}' size mismatch! Expected: {expected_size}, Actual: {actual_size}")
			else:
				logging.info(f"Channel '{channel_name}' size matches expected value.")
				reshaped_data = data.reshape((expected_height, expected_width))
				images[channel_name] = reshaped_data
				
		# Print out the channel sizes for validation
		logging.info(f"Channel Sizes: {channel_sizes}")
		
		def render_image(images, channels, full_res_size):
			plt.figure(figsize=(10, 10))
			
			# Check if we can render the image based on available channels
			if len(images) >= 3:
				# Assuming channels are in BY, RY, Y order; adjust as necessary
				combined_image = np.zeros((full_res_size[1], full_res_size[0], 3))
				channel_order = ['Y', 'RY', 'BY']  # Adjust if needed
				
				for i, channel_name in enumerate(channel_order):
					if channel_name in channels:
						logging.info(f"Using channel '{channel_name}' for combined image.")
						if images[channel_name].shape != (full_res_size[1], full_res_size[0]):
							logging.info(f"Resizing channel '{channel_name}' from {images[channel_name].shape} to {full_res_size[1], full_res_size[0]}")
							resized_channel = resize(images[channel_name], (full_res_size[1], full_res_size[0]), anti_aliasing=True)
						else:
							resized_channel = images[channel_name]
						combined_image[..., i] = resized_channel
						
				combined_image = np.clip(combined_image, 0, 1)
				plt.imshow(combined_image)
			elif 'Y' in channels and len(images) == 1:
				# Render the single Y channel if that's all we have
				plt.imshow(images['Y'], cmap='gray')
			else:
				logging.error("Unable to render the image due to an unexpected channel configuration.")
				return
			
			plt.title('Rendered EXR Image')
			plt.axis('off')
			plt.show()
			
		render_image(images, channels, size)
		
		exr_file.close()
		logging.info("EXR file processing completed and closed.")
		
		# Create a report with indented formatting
		channel_data_shapes = {k: v.shape for k, v in images.items()}
		report = (
			f"EXR File Analysis Report\n"
			f"========================\n"
			f"File: {exr_path}\n"
			f"Size: {size[0]}x{size[1]}, Total Pixels: {total_pixels}\n"
			f"Header Info:\n"
			f"  channels: {header['channels']}\n"
			f"  compression: {header['compression']}\n"
			f"  dataWindow: {header['dataWindow']}\n"
			f"  displayWindow: {header['displayWindow']}\n"
			f"  lineOrder: {header['lineOrder']}\n"
			f"  owner: {header['owner']}\n"
			f"  pixelAspectRatio: {header['pixelAspectRatio']}\n"
			f"  screenWindowCenter: {header['screenWindowCenter']}\n"
			f"  screenWindowWidth: {header['screenWindowWidth']}\n"
			f"Channel Keys: {channel_keys}\n"
			f"Channel Sizes:\n"
			f"  BY: {channel_sizes['BY']}\n"
			f"  RY: {channel_sizes['RY']}\n"
			f"  Y: {channel_sizes['Y']}\n"
			f"Channel Data Shapes:\n"
			f"  BY: {channel_data_shapes.get('BY')}\n"
			f"  RY: {channel_data_shapes.get('RY')}\n"
			f"  Y: {channel_data_shapes.get('Y')}\n"
		)
		print(report)
		
		# Print expected output format
		expected_output = (
			f"({repr(header)}, {size}, dict_keys({channel_keys}), "
			f"{{'BY': ({channel_sizes['BY'][0]},), 'RY': ({channel_sizes['RY'][0]},), 'Y': ({channel_sizes['Y'][0]},)}})"
		)
		print(f"Expected Output: {expected_output}")
		
	except Exception as e:
		logging.error(f"Error processing EXR file {exr_path}: {e}")
		
if __name__ == "__main__":
	exr_path = '/mnt/Flowers.exr'  # Update this path
	analyze_subsampling_and_render_image(exr_path)
	

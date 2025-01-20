# RunPE-ProcessEmbed
A basic RunPE function that Embed your target PE in the main process. making it more protected from debugging and reversing

## What is RunPE?
RunPE is a technique to run PE (Portable Executable like .exe files) files in your main process memory.
Using that you can **Embed** your target process inside a parent process and hide it from debugging and reversing.


## Features
- Memory PE mapping
- Basic error handling
- Notes of every part in the code to understand it better.

## Notes
- Only works with 64-bit PE bytes/files (next version i will add 32-bit support).
- Change the PE bytes to your own PE bytes in bytes.h 

(**You can convert PE File to Bytes** by this online tool: https://tomeko.net/online_tools/file_to_hex.php)

## How to use:
Basic example code with Error handling:
```cpp
int main()
{

	try {
		RunPe(bytes_to_run);
	}
	catch (const std::exception& e)
	{
		std::cout << "Found an Error: " << e.what() << std::endl;
	}
	
	
	return 0;
}
```

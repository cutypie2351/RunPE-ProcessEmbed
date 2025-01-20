
#include "runpe.h"
#include "bytes.h"


int main()
{
	MessageBoxA(NULL, "running the PE from vitrual memory", "Cutypie RunPE", NULL);

	try {
		RunPe(bytes_to_run);
	}
	catch (const std::exception& e)
	{
		std::cout << "Found an Error: " << e.what() << std::endl;
	}
	
	Sleep(100000);
	return 0;
}
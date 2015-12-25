#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <tlhelp32.h>



DWORD ProcId = 0; // THIS IS OUR GLOBAL VARIABLE FOR THE PROC ID;

void GetProcId(const char* ProcName)
{
	PROCESSENTRY32   pe32;
	HANDLE         hSnapshot = NULL;

	pe32.dwSize = sizeof( PROCESSENTRY32 );
	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if( Process32First( hSnapshot, &pe32 ) )
	{
		do{
			if( strcmp( pe32.szExeFile, ProcName ) == 0 )
				break;
		}while( Process32Next( hSnapshot, &pe32 ) );
	}

	if( hSnapshot != INVALID_HANDLE_VALUE )
		CloseHandle( hSnapshot );

	ProcId = pe32.th32ProcessID;
}

char* GetAddressOfData(DWORD pid, const char *data, size_t len)
{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if(process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);


        MEMORY_BASIC_INFORMATION info;
        std::vector<char> chunk;
        char* p = 0;

        std::cout << si.lpMaximumApplicationAddress;





        while(p < si.lpMaximumApplicationAddress)
        {



            if(VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
            {
                chunk.resize(info.RegionSize);
                SIZE_T bytesRead;


                if(ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
                {

                    for(size_t i = 0; i < (bytesRead - len); ++i)
                    {

                    	//std::cout << i;
                    	//std::cout << "\n";


                        if(memcmp(data, &chunk[i], len) == 0)
                        {
                            return (char*)p + i;
                        }
                    }
                }
                p += info.RegionSize;
                std::cout << ".";
                //std::cout << "\n";

            }
        }


    }
    return 0;
}



int main(){

	std::string ProcName;

	std::cout << "Hooking..." << std::endl;
	ProcName = "notepad++.exe";

	GetProcId(ProcName.c_str());

	std::cout << "PID: ";
	std::cout << ProcId;
	std::cout << "\n Mem-Scan Ready";


    std::string input;
    std::getline(std::cin, input);


    std::cout << "Looking for Data: " << input << "\n";

    int pid = ProcId;
    char* ret = GetAddressOfData(pid, input.c_str(), sizeof(input.c_str()));

    if(ret){
        std::cout << "Found Addr: " << (void*)ret << "\n";
        //std::cout << "Data in Addr: " << ret << "\n";
    }
    else{
        std::cout << "Not found\n";
    }

    while(true){
    std::string new1;
    std::getline(std::cin, new1);

    std::cout << "\n Changing Data ..." << std::endl;


    int newdata = 500;

          DWORD newdatasize = sizeof(newdata);

          HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

          if(WriteProcessMemory(process, (LPVOID)ret, &newdata, newdatasize, NULL)){

           std::cout << "Success!";

          } else {

           std::cout << "FAILED!";

          }

          CloseHandle(process);

    }

    return 0;
}

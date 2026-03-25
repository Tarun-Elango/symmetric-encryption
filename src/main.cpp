#include <sodium.h>
#include <iostream>
#include <string>
#include "encrypt_decrypt.cpp"


//g++ -O2 -std=c++17 main.cpp $(pkg-config --cflags --libs libsodium) -o main
//./main

static const char* MENU = R"(
  [1]  Encrypt a message
  [2]  Decrypt a message
  [0]  Exit (wipes session)

  Choice: )";

int main() {
    if (sodium_init() < 0) {
        std::cout << "libsodium failed\n";
        return 1;
    }
    clear_screen();
    startup_checks();
    //std::cout << BANNER << '\n';
    std::cout << " ┌─ SYSTEM CHECK "<< std::string(41, '-') << '\n';
    print_system_warnings();
    std::cout << " └" << std::string(56, '-') << "\\n\n";

    while(true){
        std::cout << MENU << std::flush;
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            // if EOF is reached (e.g., user presses Ctrl+D), we treat it as a signal to exit
            choice = "0";
        }

        if (choice == "1"){
            do_encrypt();
        } else if (choice == "2"){
            do_decrypt();
        } else if (choice == "0"){
            std::cout << "\n [*] Exiting. Shutdown down and clearing RAM.\n\n";
            return 0;
        } else {
            std::cout << "\n [!] Invalid choice. Please enter 1, 2, or 0.\n";
        }
    }
}

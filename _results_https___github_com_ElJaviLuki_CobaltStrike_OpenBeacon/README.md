
    ```
    ```bash
    git clone https://github.com/ElJaviLuki/CobaltStrike_OpenBeacon.git
# Cobalt Strike Beacon Open Source Implementation
## Contributing
## Disclaimer
## Getting Started
## License
## Overview
## Prerequisites
- Visual Studio: The project is built using Visual Studio, not Visual Studio Code.
- [libtomcrypt](https://github.com/libtom/libtomcrypt): A modular and portable cryptographic toolkit.
- [libtommath](https://github.com/libtom/libtommath): A fast, portable number-theoretic multiple-precision integer library.
1. Clone the repository:
2. Open the project in Visual Studio.
3. Ensure that the required dependencies (libtommath, libtomcrypt) are properly configured and linked with the project.
4. Build the project.
5. Create your `settings.h` file based on the provided template. Make sure to include your C2 Profile macros and configurations.
6. Build the project again to apply your custom settings.
7. Execute the compiled binary.
Please note that this project is not a reverse-engineered version of the Cobalt Strike Beacon but a ground-up open-source implementation. The `settings.h` file, containing macros for the C2 Profile, is .gitignored (and thus not available), as users are expected to complete it according to their preferences. Once you have your `settings.h` template ready, feel free to share and contribute.
This project is for educational and research purposes only. Use it responsibly and in compliance with applicable laws and regulations. The authors and contributors are not responsible for any misuse or damage caused by the use of this software.
This project is licensed under the [MIT License](LICENSE.md).
We welcome contributions from the community. If you have improvements, bug fixes, or new features to add, please submit a pull request. Be sure to follow the existing coding style and provide clear commit messages.
Welcome to the open-source implementation of the Cobalt Strike Beacon! This project aims to provide a fully functional, from-scratch alternative to the Cobalt Strike Beacon, offering transparency and flexibility for security professionals and enthusiasts.

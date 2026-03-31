cmake_minimum_required(VERSION 4.2.2)
project(myProject)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(nlohmann_json REQUIRED)
add_executable(mainexe main.cpp)
target_link_libraries(mainexe PRIVATE 
nlohmann_json::nlohmann_json
bcrypt
Crypt32
)
target_compile_definitions(mainexe PRIVATE UNICODE _UNICODE)
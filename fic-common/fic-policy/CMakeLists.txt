cmake_minimum_required(VERSION 3.5)

project(fic_policy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT TARGET fic-core)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-core ${CMAKE_CURRENT_BINARY_DIR}/fic-core)
endif()

add_library(fic-policy STATIC
    src/Policy.cpp
    src/PolicyApplyResult.cpp
    src/PolicyDependency.cpp
    src/PolicyDependencyConditionEvaluator.cpp
    src/PolicyTypeValue.cpp
)

target_include_directories(fic-policy
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(fic-policy PUBLIC fic-core)

install(TARGETS fic-policy ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

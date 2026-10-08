set(HELLO_SOURCE_DIR "${PROJECT_SOURCE_DIR}/apps/hello/src")

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Test Widgets Network)

add_executable(test_repolist
    test_repolist.cpp
    ${HELLO_SOURCE_DIR}/RepoListWindow.cpp
    ${HELLO_SOURCE_DIR}/RepoListWindow.h
)

target_include_directories(test_repolist PRIVATE ${HELLO_SOURCE_DIR})
target_link_libraries(test_repolist PRIVATE Qt6::Test Qt6::Widgets Qt6::Network)
add_test(NAME test_repolist COMMAND test_repolist)

add_executable(test_mirrorlist
    test_mirrorlist.cpp
    ${HELLO_SOURCE_DIR}/MirrorListWindow.cpp
    ${HELLO_SOURCE_DIR}/MirrorListWindow.h
)

target_include_directories(test_mirrorlist PRIVATE ${HELLO_SOURCE_DIR})
target_link_libraries(test_mirrorlist PRIVATE Qt6::Test Qt6::Widgets Qt6::Network)
add_test(NAME test_mirrorlist COMMAND test_mirrorlist)

set_target_properties(test_repolist test_mirrorlist PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data
     DESTINATION "${CMAKE_BINARY_DIR}/tests")

add_executable(test_onboarding
    test_onboarding.cpp
    ${HELLO_SOURCE_DIR}/home/Onboarding.cpp
    ${HELLO_SOURCE_DIR}/home/Environment.cpp
)
target_include_directories(test_onboarding PRIVATE ${HELLO_SOURCE_DIR})
target_link_libraries(test_onboarding PRIVATE Qt6::Test Qt6::Network)
add_test(NAME test_onboarding COMMAND test_onboarding)

add_executable(test_toolrunner
    test_toolrunner.cpp
    ${HELLO_SOURCE_DIR}/ToolRunner.cpp
)
target_include_directories(test_toolrunner PRIVATE ${HELLO_SOURCE_DIR})
target_link_libraries(test_toolrunner PRIVATE Qt6::Test)
add_test(NAME test_toolrunner COMMAND test_toolrunner)

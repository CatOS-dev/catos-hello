cmake_minimum_required(VERSION 4.0.0)

project(CatOSHello VERSION 0.1 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

option(BUILD_TESTS "Build tests" OFF)

add_subdirectory(apps/hello)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

set(CATOS_HELLO_STATE_DIR "/var/lib/catos-hello")

install(
    FILES data/desktop.yaml
    DESTINATION "${CATOS_HELLO_STATE_DIR}"
)

install(
    DIRECTORY data/news/
    DESTINATION "${CATOS_HELLO_STATE_DIR}/news"
    FILES_MATCHING PATTERN "*.html"
)

install(
    FILES data/applications/catos-hello.desktop
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications"
)

install(
    FILES data/applications/catos-hello.desktop
    DESTINATION "/etc/skel/.config/autostart"
)

install(
    PROGRAMS
        scripts/CollectLogs
        scripts/ResetKeyring
        scripts/RunInTerminal
        toolkits/clean
        toolkits/mirror-update
        toolkits/pac
        toolkits/pacd
        toolkits/pacr
        toolkits/pak
        toolkits/sysup
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

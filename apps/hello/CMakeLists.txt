set(APP_TARGET catos-hello)
set(APP_I18N_PREFIX catos-hello)
set(APP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(APP_TRANSLATION_DIR "${CMAKE_CURRENT_SOURCE_DIR}/translations")

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets LinguistTools Network)

set(PROJECT_SOURCES
    ${APP_SOURCE_DIR}/main.cpp
    ${APP_SOURCE_DIR}/mainwindow.cpp
    ${APP_SOURCE_DIR}/mainwindow.h
    ${APP_SOURCE_DIR}/mainwindow.ui
    ${APP_SOURCE_DIR}/AssistantTab.cpp
    ${APP_SOURCE_DIR}/AssistantTab.h
    ${APP_SOURCE_DIR}/GeneralNewsTab.cpp
    ${APP_SOURCE_DIR}/GeneralNewsTab.h
    ${APP_SOURCE_DIR}/InstallAppsTab.cpp
    ${APP_SOURCE_DIR}/InstallAppsTab.h
    ${APP_SOURCE_DIR}/PostInstallGuideTab.cpp
    ${APP_SOURCE_DIR}/PostInstallGuideTab.h
    ${APP_SOURCE_DIR}/TipsTab.cpp
    ${APP_SOURCE_DIR}/TipsTab.h
    ${APP_SOURCE_DIR}/MirrorListWindow.cpp
    ${APP_SOURCE_DIR}/MirrorListWindow.h
    ${APP_SOURCE_DIR}/RepoListWindow.cpp
    ${APP_SOURCE_DIR}/RepoListWindow.h
)

qt_add_executable(${APP_TARGET}
    ${PROJECT_SOURCES}
)

set_target_properties(${APP_TARGET} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(${APP_TARGET} PRIVATE -mno-avx512f)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${APP_TARGET} PRIVATE /arch:AVX2)
endif()

set(TS_FILES
    ${APP_TRANSLATION_DIR}/${APP_I18N_PREFIX}_zh_CN.ts
    ${APP_TRANSLATION_DIR}/${APP_I18N_PREFIX}_fr.ts
    ${APP_TRANSLATION_DIR}/${APP_I18N_PREFIX}_de.ts
)

add_custom_target(update_catos_hello_translations
    COMMAND Qt6::lupdate ${PROJECT_SOURCES} -ts ${TS_FILES}
    WORKING_DIRECTORY ${APP_SOURCE_DIR}
    COMMENT "Updating catos-hello translations"
)

qt_add_lrelease(${APP_TARGET}
    TS_FILES ${TS_FILES}
    QM_FILES_OUTPUT_VARIABLE QM_FILES
)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/translations.qrc"
[[<RCC>
    <qresource prefix="/translations">
        <file>catos-hello_zh_CN.qm</file>
        <file>catos-hello_fr.qm</file>
        <file>catos-hello_de.qm</file>
    </qresource>
</RCC>]])

qt_add_resources(APP_RESOURCES_RCC "${CMAKE_CURRENT_BINARY_DIR}/translations.qrc")
target_sources(${APP_TARGET} PRIVATE ${APP_RESOURCES_RCC})

target_compile_options(${APP_TARGET} PRIVATE -fsanitize=address)
target_link_options(${APP_TARGET} PRIVATE -fsanitize=address)

target_include_directories(${APP_TARGET} PRIVATE ${APP_SOURCE_DIR})
target_link_libraries(${APP_TARGET} PRIVATE Qt6::Widgets Qt6::Network)

install(
    TARGETS ${APP_TARGET}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
    FILES ${QM_FILES}
    DESTINATION "${CMAKE_INSTALL_DATADIR}/catos-hello/translations"
)

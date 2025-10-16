cmake_minimum_required(VERSION 3.16)

project(Test1 VERSION 0.1 LANGUAGES C CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Paths to Npcap SDK
set(NPCAP_INCLUDE_DIR "C:/Program Files/Npcap-SDK/Include")
set(NPCAP_LIB_DIR "C:/Program Files/Npcap-SDK/Lib")

# Paths to WinDivert
set(WINDIVERT_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/include/windivert")
set(WINDIVERT_LIB_DIR "${CMAKE_SOURCE_DIR}/lib")

# Qt setup
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    test.h
    test.c
    SYNLocalLinux.c
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(Test1
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        SYNLocalLinux.h
        windivert.h
        functions.c
        functions.h
        capture.cpp
        capture.h
        packetcapture.h packetcapture.cpp
        sendUDPPacket.c
        sendUDPPacket.h





    )
else()
    add_executable(Test1 ${PROJECT_SOURCES})
endif()

# Include paths (like -I)
target_include_directories(Test1 PRIVATE
    ${NPCAP_INCLUDE_DIR}
    ${WINDIVERT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/lib/include/npcap-bpf
    ${CMAKE_SOURCE_DIR}/lib/include/npcap-defs
)

# Link directories (like -L)
target_link_directories(Test1 PRIVATE
    ${NPCAP_LIB_DIR}
    ${WINDIVERT_LIB_DIR}

)
#link_directories(${CMAKE_SOURCE_DIR}/lib/WinDivert.lib)

# Link libraries (like -l)
target_link_libraries(Test1 PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    ws2_32
    wpcap
    #WinDivert
    ${CMAKE_SOURCE_DIR}/lib/WinDivert.lib
)

# Copy DLLs & SYS after build
add_custom_command(TARGET Test1 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_LIB_DIR}/wpcap.dll
        ${WINDIVERT_LIB_DIR}/WinDivert.dll
        ${WINDIVERT_LIB_DIR}/WinDivert64.sys
        $<TARGET_FILE_DIR:Test1>
)

# Windows + macOS bundle setup (safe to leave as is)
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.Test1)
endif()

set_target_properties(Test1 PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Install step (optional)
include(GNUInstallDirs)
install(TARGETS Test1
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Finalize if Qt 6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(Test1)
endif()

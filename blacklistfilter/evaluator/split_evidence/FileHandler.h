#ifndef UNTITLED1_FILEHANDLER_H
#define UNTITLED1_FILEHANDLER_H


#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <map>

#include <unirec/unirec2csv.h>

#define BUFF_SIZE 131072

class FileHandler {

    //Structure holding buffer
    struct TFileWrap {
        std::string m_filename;
        char m_buffer[BUFF_SIZE];
        size_t m_buffer_len;
        std::chrono::time_point<std::chrono::system_clock> m_last_write;

        TFileWrap( const std::string& file, urcsv_t* csv );
        ~TFileWrap();
        void write(  const void* in_rec, urcsv_t* csv );
    };
    //Map with files held in memory
    std::map<std::string, FileHandler::TFILE_WRAP*> m_files;

    //Path to a folder where files will be created
    std::string m_path;

    //Interval in which the the module check m_last_write variable
    std::chrono::milliseconds m_check_interval;

    //If no write occured during this time, the buffer is flushed
    std::chrono::milliseconds m_close_timeout;

    //Indicates the termination of the module
    bool m_stop;

    std::thread m_watcher;
    std::condition_variable m_cond;
    std::mutex m_mtx;

    void closed_unused_files();
    void stop_handler();

public:

    FileHandler( const std::string& path, const std::chrono::milliseconds& check_interval, const std::chrono::milliseconds& close_timeout );
	~FileHandler();
    void start_handler();

    void write_to_file( const std::string& filename, const void* in_rec, urcsv_t* csv );

};


#endif //UNTITLED1_FILEHANDLER_H

#include "FileHandler.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <sys/stat.h>

FileHandler::TFileWrap::TFileWrap(const std::string& filename, urcsv_t* csv ) 
: m_filename( filename ),
m_buffer_len( 0 ) {

    struct stat stat_struct;
    if( stat(filename.c_str(), &stat_struct) != 0 ) {
        char* hdr = urcsv_header(csv);
        m_buffer_len = std::snprintf( &m_buffer[m_buffer_len], BUFF_SIZE, "%s\n", hdr );
        free(hdr);
    }

    m_last_write = std::chrono::system_clock::now();

}

FileHandler::TFileWrap::~TFileWrap() {
    
    if( m_buffer_len ) {    
        std::ofstream ofs( m_filename, std::ios::app );
        ofs << m_buffer;
    }

}

void FileHandler::TFileWrap::write( const void* in_rec, urcsv_t* csv) {

    char *rec = urcsv_record(csv, in_rec);
    size_t rec_len = std::strlen( rec );

    //Append the record to the buffer if there is still free capacity, flush to the file otherwise
    if( m_buffer_len + rec_len + 1 < BUFF_SIZE ) {
        m_buffer_len += std::snprintf( &m_buffer[m_buffer_len], BUFF_SIZE - m_buffer_len, "%s\n", rec );
    } else {
        std::ofstream ofs( m_filename, std::ios::app );
        ofs << m_buffer << rec << '\n';
        m_buffer_len = 0;
    }
    free( rec );

    //Update the timestamp
    m_last_write = std::chrono::system_clock::now();

}

FileHandler::FileHandler(const std::string &path, const std::chrono::milliseconds &check_interval,
                         const std::chrono::milliseconds &close_timeout) :
                         m_path( path ),
                         m_check_interval( check_interval ),
                         m_close_timeout( close_timeout ),
                         m_stop( true ){
    if( m_path.back() != '/' )
        m_path.append( 1, '/' );

}

FileHandler::~FileHandler() {
	stop_handler();
	for (auto it = m_files.begin(); it != m_files.end(); ++it) {
        	delete it->second;
        }
}
void FileHandler::closed_unused_files() {

    while( ! m_stop ) {
        std::unique_lock<std::mutex> lock(m_mtx);

        //Wait for check_interval to expire or termination
	    m_cond.wait_for(lock, m_check_interval, [this]() { return m_stop; });

        for (auto it = m_files.begin(); it != m_files.end();) {
            
            //Get the time since the last write
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now() - it->second->m_last_write);

            if ( diff > m_close_timeout ) {
                delete it->second;
                it = m_files.erase(it);
            } else {
                ++it;
            }
        }

        lock.unlock();
    }

}

void FileHandler::start_handler() {

    m_stop = false;
    m_watcher = std::thread( &FileHandler::closed_unused_files, this );

}

void FileHandler::stop_handler() {

    {
        std::unique_lock<std::mutex> lock( m_mtx );
        m_stop = true;
    }

    m_cond.notify_one();
    m_watcher.join();

}

void FileHandler::write_to_file( const std::string& filename, const void* in_rec, urcsv_t* csv ) {

    std::unique_lock<std::mutex> lock( m_mtx );

    auto it = m_files.find( filename );
    if( it != m_files.end() ) {
        it->second->write( in_rec, csv );
    } else {
        try {
            auto file_it = m_files.insert(std::make_pair(filename, new FileHandler::TFileWrap( m_path + filename + ".csv", csv )));
            file_it.first->second->write( in_rec, csv );
        } catch ( const std::bad_alloc &e ) {
            //Memory allocation failed
            std::cerr << e.what() << '\n';
        }
    }
}


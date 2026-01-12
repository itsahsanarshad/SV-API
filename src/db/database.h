#pragma once

#include <pqxx/pqxx>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include "config/config.h"

namespace db {

class ConnectionPool {
public:
    explicit ConnectionPool(const std::string& connection_string, size_t pool_size = 10)
        : connection_string_(connection_string), pool_size_(pool_size) {
        for (size_t i = 0; i < pool_size_; ++i) {
            connections_.push(std::make_shared<pqxx::connection>(connection_string_));
        }
    }

    std::shared_ptr<pqxx::connection> acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !connections_.empty(); });

        auto conn = connections_.front();
        connections_.pop();
        return conn;
    }

    void release(std::shared_ptr<pqxx::connection> conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_.push(conn);
        cv_.notify_one();
    }

private:
    std::string connection_string_;
    size_t pool_size_;
    std::queue<std::shared_ptr<pqxx::connection>> connections_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

class Database {
public:
    explicit Database(const config::DatabaseConfig& config, size_t pool_size = 10)
        : pool_(std::make_unique<ConnectionPool>(config.connection_string(), pool_size)) {}

    class Connection {
    public:
        Connection(ConnectionPool& pool) : pool_(pool), conn_(pool.acquire()) {}
        ~Connection() { pool_.release(conn_); }

        pqxx::connection& get() { return *conn_; }

        Connection(const Connection&) = delete;
        Connection& operator=(const Connection&) = delete;

    private:
        ConnectionPool& pool_;
        std::shared_ptr<pqxx::connection> conn_;
    };

    Connection get_connection() {
        return Connection(*pool_);
    }

    template<typename T>
    pqxx::result execute(const std::string& query) {
        auto conn = get_connection();
        pqxx::work txn(conn.get());
        auto result = txn.exec(query);
        txn.commit();
        return result;
    }

    pqxx::result query(const std::string& sql) {
        auto conn = get_connection();
        pqxx::work txn(conn.get());
        auto result = txn.exec(sql);
        txn.commit();
        return result;
    }

    pqxx::result query_params(pqxx::zview sql, const pqxx::params& params) {
        auto conn = get_connection();
        pqxx::work txn(conn.get());
        auto result = txn.exec(sql, params);
        txn.commit();
        return result;
    }

    void execute_non_query(const std::string& sql) {
        auto conn = get_connection();
        pqxx::work txn(conn.get());
        txn.exec(sql);
        txn.commit();
    }

    void execute_non_query_params(pqxx::zview sql, const pqxx::params& params) {
        auto conn = get_connection();
        pqxx::work txn(conn.get());
        txn.exec(sql, params);
        txn.commit();
    }

private:
    std::unique_ptr<ConnectionPool> pool_;
};

inline std::shared_ptr<Database> create_database(const config::DatabaseConfig& config) {
    return std::make_shared<Database>(config);
}

} // namespace db

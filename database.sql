create database company;             
use company;

create table users (
    id INT PRIMARY KEY,
    name VARCHAR(32),
    public_key VARCHAR(32) NOT NULL,
    password VARCHAR(32) NOT NULL
);

create table buckets (
    name varchar(100) PRIMARY KEY,
    user_id INT NOT NULL,
    private_key VARCHAR(32) NOT NULL,
    foreign key (user_id) references users (id)
);

create table groups (
    bucket_name varchar(100) NOT NULL,
    user_id INT NOT NULL,
    private_key VARCHAR(32) NOT NULL,
    foreign key (bucket_name) references buckets (name)
);
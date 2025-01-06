import json
import re
from logging import exception

from pymongo import MongoClient, UpdateOne
import datetime

from datetime import datetime, timezone, timedelta
import pytz
import schedule

import threading
import time

import sys

import os
import zipfile
import requests
# 打开一个文件以进行写入（会覆盖原有内容）

# 连接到MongoDB
username = 'lcl'
password = 'lcl123lcl'
host = 'localhost'
port = 27037
database_name = 'sca'
uri = f'mongodb://{username}:{password}@{host}:{port}/{database_name}'
client_a = MongoClient(uri)
db_a = client_a[database_name]
username = 'xucg'
password = 'iscas139'
host = '192.168.59.201'
port = 27018
uri = f'mongodb://{username}:{password}@{host}:{port}'  # 加了这个admin之后跑时间变长了，但是一直不打印，应该还是有问题。不管了先吃饭了！
client_b = MongoClient(uri)

col_vuln = db_a['query_for_vuln_agg']
std_time = time.time()-349200
cnt = 0

def convert_to_timestamp(time_str):
    if not time_str:
        #print('Invalid input: empty string')
        return 0
    #print(time_str)
    # 定义三种时间格式
    time_format_1 = "%Y-%m-%dT%H:%M:%S.%f%z"  # 包含微秒和时区
    time_format_2 = "%Y-%m-%dT%H:%M:%SZ"  # 不含微秒的UTC时间
    time_format_3 = "%Y-%m-%dT%H:%M:%S"  # 不含微秒和时区

    try:
        # 尝试解析不含时区和微秒的格式
        try:
            dt_obj = datetime.strptime(time_str, time_format_3)
            #print('Parsed with format 3')
            # 假设时间为 UTC 时间
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
            return dt_obj.timestamp()
        except ValueError:
            pass  # 如果格式不匹配，尝试下一种格式

        # 尝试解析不含微秒但带 UTC 时区的格式
        try:
            dt_obj = datetime.strptime(time_str, time_format_2)
            #print('Parsed with format 2')
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            return dt_obj.timestamp()
        except ValueError:
            pass

        # 尝试解析带微秒和时区的格式
        if '.' not in time_str:
            time_str = time_str[:-6] + '.000000' + time_str[-6:]

        try:
            dt_obj = datetime.strptime(time_str, time_format_1)
            if dt_obj.year < 1970 or dt_obj.year > datetime.now().year:
                return 0
            #print('Parsed with format 1')
            return dt_obj.timestamp()
        except ValueError:
            print('Failed to parse time string')
            return 0

    except Exception as e:
        # 捕获任何其他异常
        print(f"Error: {e},{name},{source}")
        return 0

def download_zip(url, save_path):
    response = requests.get(url)
    response.raise_for_status()  # 确保请求成功
    with open(save_path, 'wb') as file:
        file.write(response.content)
    print(f"ZIP 文件已下载到: {save_path}")

# 解压 ZIP 文件
def extract_zip(zip_path, extract_to_folder):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to_folder)
    print(f"ZIP 文件已解压到: {extract_to_folder}")


def process_json_files(folder_path):
    # 遍历文件夹中的每个文件和子文件夹
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            # 只处理 .json 文件
            if file.endswith(".json"):
                json_file_path = os.path.join(root, file)
                try:
                    # 打开并加载 JSON 文件
                    with open(json_file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        #print(f"处理文件: {json_file_path}")

                        # 在这里可以对 data 进行处理
                        process_json(data)

                except Exception as e:
                    print(f"无法处理文件 {json_file_path}: {e}")

def process_json(data):
    #json_data = data
    global std_time, cnt
    # 将字符串转为 Python 对象
    #data = json.loads(json_data)

    # 提取 'id' 字段
    # osv_id = data['id'] #这里没用，因为不是以cve为id存的
    # print(f"osv_id: {osv_id}")
    if data['modified'] and data['published']:
        data_update_time = max(convert_to_timestamp(data['modified']),convert_to_timestamp(data['published']))
    else:
        data_update_time = convert_to_timestamp(data['published'])
    if data_update_time > std_time:
        # 提取 'aliases' 中以 "CVE" 开头的项
        cve_ids = []
        for alias in data['aliases']:
            if alias.startswith("CVE"):
                cve_ids.append(alias)
        #print(f"cve_id: {cve_ids}")

        # 提取 'affected' 字段中的数据
        for affected_item in data['affected']:
            # 获取 'package' 字段中的 'name' 和 'ecosystem'
            name = affected_item['package']['name']
            source = affected_item['package']['ecosystem']
            #print(f"Package Name: {name}, Ecosystem: {source}")

            # 遍历 'versions' 字段
            for version in affected_item['versions']:
                #print(f"  Version: {version}")
                query = {'name': name, 'source': source.lower(), 'version': version}
                matches = col_vuln.count_documents(query)
                print(source,name,matches)
                if matches:
                    for cve_id in cve_ids:
                        col_vuln.update_many(query, {"$addToSet": {"cve_ids": cve_id}})
                else:
                    cnt = cnt + 1
                    doc = {
                        'name': name,
                        'source': source.lower(),
                        'version': version,
                        'cve_ids': cve_ids
                    }
                    col_vuln.insert_one(doc)


def delete_all_files_in_directory(directory_path):
    """
    删除指定路径下的所有文件，保留目录本身。

    :param directory_path: 目标目录路径
    """
    # 确保目标路径存在且是一个目录
    if not os.path.isdir(directory_path):
        print(f"错误: {directory_path} 不是一个有效的目录。")
        return

    # 遍历目录中的所有文件和子目录
    for root, dirs, files in os.walk(directory_path, topdown=False):  # 从文件到目录
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # 删除文件
                os.remove(file_path)
                print(f"已删除文件: {file_path}")
            except Exception as e:
                print(f"无法删除文件 {file_path}: {e}")

def main():
    sources = ['PyPI', 'crates.io', 'Go', 'Maven', 'npm', 'NuGet', 'Packagist', 'Pub', 'CRAN','Chainguard', 'RubyGems']
    extract_folder = "D:\isrc\data\data_sources"  # 解压文件的目标文件夹
    for data_source in sources:
        #print(1)
        zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{data_source}/all.zip"  # 替换为你想要下载的 ZIP 文件 URL
        #print(2)
        zip_file_path = f"D:\isrc\data\data_sources\\{data_source}.zip"  # 下载后的文件路径
        

        # 下载并解压
        download_zip(zip_url, zip_file_path)

        # 创建目标文件夹（如果不存在）
        if not os.path.exists(extract_folder):
            os.makedirs(extract_folder)

        # 解压 ZIP 文件
        extract_zip(zip_file_path, extract_folder)

    process_json_files(extract_folder)
    delete_all_files_in_directory(extract_folder)

def task():
    start_time = time.time()
    main()
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"The loop ran for {elapsed_time:.4f} seconds.")
    print(f'added {cnt} docs')

if __name__ == '__main__':
    schedule.every().day.at("14:07").do(task)
    print("Scheduled jobs:", schedule.get_jobs())

    # 进入一个循环，每天执行一次任务
    while True:
        schedule.run_pending()
        time.sleep(60)

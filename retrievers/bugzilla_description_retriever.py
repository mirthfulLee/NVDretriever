import requests
import csv
import time
import json
import logging
import pandas as pd
import threading
import os
import random

bug_info_columns = {
    # bugzilla columns
    "bugzilla_id": str,
    "product": str,
    "component": str,
    "priority": str,
    "severity": str,
    "summary": str,
    "created": str,
    # description_columns
    "description_id": int,
    "text": str,  # ! 可能比raw_text多一些特殊的文本
    # "raw_text": str, # ! 有些网站的API不提供该字段
    "is_private": bool,
    # "is_markdown": bool, # ! 有些网站的API不提供该字段
}


def get_logger(logger_name, log_file, level=logging.INFO):
    logger = logging.getLogger(logger_name)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s", "%m-%d %H:%M:%S"
    )
    fileHandler = logging.FileHandler(log_file, mode="a")
    fileHandler.setFormatter(formatter)

    logger.setLevel(level)
    logger.addHandler(fileHandler)
    return logger


def get_comments_of_bug(domain, bug_id, logger, headers=None, params=None):
    sleep_gap = random.randint(15, 45)
    for _ in range(5):
        try:
            resp = requests.get(
                "{}/rest/bug/{}/comment".format(domain, bug_id),
                headers=headers,
                params=params,
            )
            if resp.status_code >= 400:
                raise requests.RequestException()
        except:
            logger.error(
                "**** can not get the responce of BR-{}, request again".format(bug_id)
            )
            time.sleep(sleep_gap)
            continue
        try:
            comments = json.loads(resp.text).get("bugs").get(bug_id).get("comments")
            if comments is None:
                raise json.JSONDecodeError()
            return comments
        except:
            logger.error(
                "**** can not deserialize responce of {}, request again".format(bug_id)
            )
            time.sleep(sleep_gap)
    return None


def get_description_of_product(product, domain, offset=0):
    des_number_per_request = 500
    short_product_name = product.replace("/", " ")
    logger = get_logger(
        product, os.path.join(log_dir, "{}.log".format(short_product_name))
    )
    logger.critical(
        "**** START to retrieve BR description of product {} ***".format(product)
    )
    BR_file = os.path.join(BR_dir, "{}.csv".format(short_product_name))
    result_file = os.path.join(result_dir, "{}.csv".format(short_product_name))
    csv_f = open(result_file, mode="a", newline="", encoding="utf-8")
    fw = csv.writer(csv_f)
    if not os.path.getsize(result_file):
        fw.writerow(bug_info_columns.keys())
        csv_f.flush()

    BR_chunks = pd.read_csv(
        BR_file,
        chunksize=des_number_per_request,
        dtype=str,
        skiprows=range(1, offset + 1),
        header=0,
    )
    go_ahead = True
    for BR_chunk in BR_chunks:
        logger.info(
            "retrieving description of {} between {} and {}".format(
                product, offset, offset + des_number_per_request
            ),
        )

        # *save each bug report to a csv row
        for index, bug_report in BR_chunk.iterrows():
            bug_id = bug_report["bugzilla_id"]
            comments = get_comments_of_bug(domain, bug_id, logger=logger)
            if comments is None:
                logger.error(
                    "!!!! can not find the description of BR-{} !!!!".format(bug_id)
                )
                print(product + "," + domain + "," + bug_id)
                go_ahead = False
                break
            offset += 1
            if len(comments) == 0:
                logger.error("#### BR-{} has no description ####".format(bug_id))
                continue
            description = comments[0]
            cur_row = bug_report.to_dict()
            # * add columns of description
            cur_row["description_id"] = description["id"]
            cur_row["text"] = description["text"]
            # cur_row["raw_text"] = description["raw_text"]
            cur_row["is_private"] = description["is_private"]
            # cur_row["is_markdown"] = description["is_markdown"]
            # FIXME: 换行符转义

            fw.writerow(cur_row.values())
        csv_f.flush()
        if not go_ahead:
            break

    logger.critical(
        "**** DONE the retrieving process of product {} ***".format(product)
    )
    print("{},{},{}".format(product, domain, offset))
    product_infos.at[product, "offset"] = offset
    product_infos.to_csv(product_info_file, header=True, index=True)
    csv_f.close()
    if multi_thread:
        pool_sema.release()
    


if __name__ == "__main__":
    BR_dir = "../result_data/bugzilla_reports"
    result_dir = "../result_data/BR_with_description"
    log_dir = "../logs/retrieve_BR_description"
    # 暂时不处理 File System;Drivers;Core
    product_info_file = "../result_data/description_process.csv"
    product_infos = pd.read_csv(product_info_file, index_col="product")
    multi_thread = False
    if multi_thread:
        max_connections = 5
        pool_sema = threading.Semaphore(max_connections)
    threads = []
    for product, p in product_infos.iterrows():
        if multi_thread:
            pool_sema.acquire()
            product_thread = threading.Thread(
                target=get_description_of_product,
                args=(product, p["bugzilla_domain"], p["offset"]),
            )
            product_thread.start()
            time.sleep(3)
            threads.append(product_thread)
        else:
            get_description_of_product(product, p["bugzilla_domain"], p["offset"])

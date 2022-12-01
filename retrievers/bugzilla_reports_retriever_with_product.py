import requests
import csv
import time
import json
import logging
import pandas as pd
import threading
import os


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


def get_bug_infos(rest_api, logger, headers=None, params=None):
    for _ in range(4):
        try:
            resp = requests.get(rest_api, headers=headers, params=params)
            if resp.status_code >= 400:
                raise requests.RequestException("Failure in request")
        except:
            logger.error("**** did not get the target responce, request again")
            time.sleep(10)
            continue
        try:
            bugzilla_bug_infos = json.loads(resp.text).get("bugs")
            if bugzilla_bug_infos is None:
                raise json.JSONDecodeError("Failure in decode responce body")
            return bugzilla_bug_infos
        except:
            logger.error("**** can not deserialize the responce body, request again")
            time.sleep(10)

    return None


target_columns = {
    # bugzilla columns
    "bugzilla_id": str,
    "product": str,
    "component": str,
    "priority": str,
    "severity": str,
    "summary": str,
    "created": str,
    # ! "comment": str, # 暂时先不获取， 之后和nCBR一起获取
}


def get_buginfo_of(product, domain, offset=0):
    short_product_name = product.replace("/", " ")
    logger = get_logger(
        product, "../logs/retrieve_BR/{}.log".format(short_product_name)
    )
    logger.critical(
        "**** START the retrieving process of product {} ***".format(product)
    )
    bug_number_per_request = 500
    result_file = "../result_data/bugzilla_reports/{}.csv".format(short_product_name)
    csv_f = open(result_file, mode="a", newline="", encoding="utf-8")
    fw = csv.writer(csv_f)
    if not os.path.getsize(result_file):
        fw.writerow(target_columns.keys())
        csv_f.flush()
    while True:
        logger.info(
            "retrieving reports of {} between {} and {}".format(
                product, offset, offset + bug_number_per_request
            ),
        )
        params = {"product": product, "offset": offset, "limit": bug_number_per_request}
        bugzilla_bug_infos = get_bug_infos(
            domain + r"/rest/bug", logger=logger, params=params
        )
        if bugzilla_bug_infos is None:
            logger.error(
                "!!!!!!!!! failed when retrieving reports of {} between {} and {} !!!!!!!!".format(
                    product, offset, offset + bug_number_per_request
                )
            )
            print(product + "," + domain)
            break
        # * 结束标志： body的bugs列表为空
        if len(bugzilla_bug_infos) == 0:
            break
        offset += bug_number_per_request
        # *save each bug report to a csv row
        for bugzilla_bug_info in bugzilla_bug_infos:
            cur_row = {}
            # bugzilla columns
            cur_row["bugzilla_id"] = bugzilla_bug_info.get("id")
            cur_row["product"] = bugzilla_bug_info.get("product")
            cur_row["component"] = bugzilla_bug_info.get("component")
            cur_row["priority"] = bugzilla_bug_info.get("priority")
            cur_row["severity"] = bugzilla_bug_info.get("severity")
            cur_row["summary"] = bugzilla_bug_info.get("summary")
            cur_row["created"] = bugzilla_bug_info.get("creation_time")

            fw.writerow(cur_row.values())
        csv_f.flush()

    logger.critical(
        "**** retrieving process of product {} have DONE ***".format(product)
    )
    csv_f.close()
    # ! update offset
    product_info.at[product, "offset"] = offset

    if multi_thread:
        pool_sema.release()


product_info_file = "../result_data/product_process.csv"
product_info = pd.read_csv(product_info_file, index_col="product")
multi_thread = False
max_connections = 5
if multi_thread:
    pool_sema = threading.Semaphore(max_connections)

if __name__ == "__main__":
    threads = []
    for product, info in product_info.iterrows():
        if multi_thread:
            pool_sema.acquire()
            product_thread = threading.Thread(
                target=get_buginfo_of,
                args=(product, info["bugzilla_domain"], info["offset"]),
            )
            product_thread.start()
            threads.append(product_thread)
        else:
            get_buginfo_of(product, info["bugzilla_domain"], info["offset"])

    product_info.to_csv(product_info_file, index=True, header=True)

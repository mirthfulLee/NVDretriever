# coding=utf-8
# TODO: 删除无用的换行符
# TODO：合并description和CIR字段
# TODO：统一字段名
# TODO：统一文件格式为json？
# TODO：把非alpha字符进行替换
# TODO：处理code snippet?
# TODO：处理http reference?
# TODO：处理过长的description
import pandas as pd
import os
import re
import csv
import json
from processor_for_bugzilla_reports import replace_tokens_simple


def process_bugzilla_reports(product_list: list, SBR_df: pd.DataFrame):
    """process description, title, and get security_relevent column"""
    for product in product_list:
        BR_file = os.path.join(BR_dir, product.replace("/", "_") + ".csv")
        BR_df = pd.read_csv(BR_file, header=0, nrows=20)
        BR_df.insert(BR_df.shape[1], "security_relevent", False)
        # ! "Platform Specific/Hardware" "IO/Storage"
        relevent_SBR = SBR_df.loc[SBR_df["product"] != BR_file[:-4]]
        BR_df["security_relevent"] = BR_df["bugzilla_id"].map(
            lambda x: x in relevent_SBR["bugzilla_id"]
        )
        BR_df["summary"] = BR_df["summary"].map(replace_tokens_simple)
        BR_df["text"] = BR_df["text"].map(replace_tokens_simple)

        # save propossed result
        processed_BR_file = os.path.join(
            processed_BR_dir, product.replace("/", "_") + ".csv"
        )
        BR_df.to_csv(processed_BR_file, header=True, index=False)


def process_SBR(SBR_df: pd.DataFrame):
    SBR_df["summary"] = SBR_df["summary"].map(replace_tokens_simple)
    SBR_df["description"] = SBR_df["description"].map(replace_tokens_simple)
    SBR_df.to_csv(processed_SBR_file, header=True, index=False)


if __name__ == "__main__":
    filtered_SBR_file = "../result_data/SBR.csv"
    processed_SBR_file = "../result_data/SBR_processed.csv"
    product_info_file = "../result_data/product_info.csv"
    BR_dir = "../result_data/BR_with_description/"
    reports_info_dir = "../result_data/bugzilla_bug_reports/"
    processed_BR_dir = "../result_data/BR_processed/"

    SBR_df = pd.read_csv(filtered_SBR_file, header=0)
    product_info = pd.read_csv(product_info_file, header=0)
    product_list = product_info["product"].to_list()
    process_SBR(SBR_df)
    process_bugzilla_reports(product_list, SBR_df)

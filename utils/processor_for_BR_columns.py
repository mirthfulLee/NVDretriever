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
from processor_for_bugzilla_reports import replace_tokens_simple


def process_bugzilla_reports(product_info: pd.DataFrame, SBR_df: pd.DataFrame):
    """process description, title, and get security_relevent column"""
    product_list = product_info.index.to_list()
    detailed_product_info = product_info
    # * get detailed product info - BR_num, SBR_num
    detailed_product_info["BR_num"] = 0
    detailed_product_info["SBR_num"] = 0
    for product in product_list:
        print("#### start to process reports of {} ###".format(product))
        BR_file = os.path.join(BR_dir, product.replace("/", "_") + ".csv")
        # BR_df = pd.read_csv(BR_file, header=0, nrows=20)
        chunk_size = 2000
        BR_chunks = pd.read_csv(BR_file, header=0, chunksize=chunk_size)
        # ! "Platform Specific/Hardware" "IO/Storage"
        relevent_SBR = SBR_df.loc[SBR_df["product"] == product]
        detailed_product_info.at[product, "SBR_num"] = relevent_SBR.shape[0]
        cnt = 0
        for BR_df in BR_chunks:
            print(
                "|-- process between {} and {}".format(
                    cnt * chunk_size, (cnt + 1) * chunk_size - 1
                )
            )
            BR_df["security_relevent"] = BR_df["bugzilla_id"].map(
                lambda x: x in relevent_SBR["bugzilla_id"]
            )
            BR_df["summary"] = BR_df["summary"].map(replace_tokens_simple)
            BR_df["text"] = BR_df["text"].map(replace_tokens_simple)

            detailed_product_info.at[product, "BR_num"] += BR_df.shape[0]
            # save propossed result
            processed_BR_file = os.path.join(
                processed_BR_dir, product.replace("/", "_") + ".csv"
            )
            if cnt == 0:
                BR_df.to_csv(processed_BR_file, mode="w", header=True, index=False)
            else:
                BR_df.to_csv(processed_BR_file, mode="a", header=False, index=False)
            cnt += 1

    detailed_product_info.to_csv(detailed_product_info_file, index=True, header=True)


def process_SBR(SBR_df: pd.DataFrame):
    SBR_df["summary"] = SBR_df["summary"].map(replace_tokens_simple)
    SBR_df["description"] = SBR_df["description"].map(replace_tokens_simple)
    SBR_df.to_csv(processed_SBR_file, header=True, index=False)


if __name__ == "__main__":
    filtered_SBR_file = "../result_data/SBR.csv"
    processed_SBR_file = "../result_data/SBR_processed.csv"
    product_info_file = "../result_data/product_info.csv"
    detailed_product_info_file = "../result_data/detailed_product_info.csv"
    BR_dir = "../result_data/BR_with_description/"
    reports_info_dir = "../result_data/bugzilla_bug_reports/"
    processed_BR_dir = "../result_data/BR_processed/"

    SBR_df = pd.read_csv(filtered_SBR_file, header=0)
    product_info = pd.read_csv(product_info_file, header=0, index_col="product")
    process_SBR(SBR_df)
    process_bugzilla_reports(product_info, SBR_df)

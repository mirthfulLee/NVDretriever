import pandas as pd
import os

if __name__ == "__main__":
    temp_path = "./result_data/BR_with_description"
    result_file = "./result_data/description_process.csv"
    product_cnt = pd.read_csv(result_file, index_col="product")
    # !临时删除部分product
    file_list = os.listdir(temp_path)
    excluded_products = [p[:-4] for p in file_list]
    excluded_products.remove(".git")
    excluded_products = [
        p if p != "IO Storage" else "IO/Storage" for p in excluded_products
    ]
    excluded_products = [
        p if p != "Platform Specific Hardware" else "Platform Specific/Hardware"
        for p in excluded_products
    ]
    product_cnt = product_cnt.drop(index=excluded_products, axis=0)

    product_cnt.to_csv(result_file, index=True, header=True)

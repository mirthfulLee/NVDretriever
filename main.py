import sys
import pandas as pd

if __name__ == "__main__":
    product_info_file = "./result_data/product_info.csv"
    result_file = "./result_data/description_process.csv"
    product_info = pd.read_csv(product_info_file, header=0, index_col="product")
    str_list = []
    for line in sys.stdin:
        s = line[:-1]
        if s == "%%":
            break
        str_list.append(s)
    df = pd.DataFrame(columns=["bugzilla_domain"], index=["product"])
    for s in str_list:
        df.loc[s] = product_info.loc[s]
    df["offset"] = 0
    df.to_csv(result_file, header=True, index=True)

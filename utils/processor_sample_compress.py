# TODO: target: 
# 1. add CVE_Description (preprocessed) and CWE_ID col
# 2. remove irrelevant columns, (Issue_Title, Issue_Body, CVE_Description, CWE_ID)
import pandas as pd
import json
from processor_for_bugzilla_reports import replace_tokens_simple

def compress_samples(target="train_samples"):
    IR_file = data_root +target+ ".json"
    CVE_dict_file = data_root + "CVE_dict_merged.json"
    IRs = pd.read_json(IR_file)
    CVE_dict = json.load(open(CVE_dict_file, "r"))
    IRs["CWE_ID"] = ""
    IRs["CVE_Description"] = ""
    for i, ir in IRs.iterrows():
        if ir["Security_Issue_Full"] == 1:
            IRs.at[i, "CWE_ID"] = CVE_dict[ir["CVE_ID"]]["CWE_ID"]
            IRs.at[i, "CVE_Description"] = replace_tokens_simple(CVE_dict[ir["CVE_ID"]]["CVE_Description"])
    
    IRs = IRs.loc[:, ["Issue_Title", "Issue_Body", "CVE_Description", "CWE_ID"]]
    
    compressed_file = data_root+target+"_compressed.csv"
    IRs.to_csv(compressed_file, index=False, header=True)

def compress_CVE_dict():
    CVE_dict_file = data_root + "CVE_dict.json"
    CVE_dict = pd.read_json(CVE_dict_file, orient="index")
    CVE_dict["CVE_Description"] = CVE_dict["CVE_Description"].map(replace_tokens_simple)
    CVE_dict = CVE_dict.loc[:, ["CWE_ID", "CVE_Description"]]
    CVE_dict.to_csv(data_root+"CVE_text.csv", header=True, index=False)


if __name__ == "__main__":
    data_root = "../result_data/"
    # compress_CVE_dict()
    compress_samples("train_samples")
    compress_samples("validation_samples")
    compress_samples("test_samples")

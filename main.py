import pandas as pd
import os
import csv


if __name__ == "__main__":
    csv_file = "./result_data/bugzilla_reports/BR_of_389.csv"
    df_chunks = pd.read_csv(
        csv_file, dtype=str, header=0, skiprows=range(1, 5), chunksize=5
    )
    result_file = "temp_test.csv"
    csv_f = open(result_file, mode="a", newline="", encoding="utf-8")
    fw = csv.writer(csv_f)
    if not os.path.getsize(result_file):
        print("asbkjghajkshkjdfashkjdhaskjdh")
        print(os.path.getsize(result_file))

    # for df in df_chunks:
    #     print(df)

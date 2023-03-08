import sys
import pandas as pd
import os

if __name__ == "__main__":
    data_root = "./result_data/"
    product_info_file = os.path.join(data_root, "product_info.csv")
    product_info = pd.read_csv(product_info_file)
    for _, product_row in product_info.iterrows():
        product = product_row["product"]
        reports_file = os.path.join(
            data_root, "BR_complete_processed", product.replace("/", "_") + ".csv"
        )

        reports = pd.read_csv(
            reports_file,
            usecols=[
                "bugzilla_id",
                "product",
                "component",
                "priority",
                "severity",
                "summary",
                "created",
                "description_id",
                "text",
                "is_private",
            ],
        )
        reports.to_csv(reports_file, header=True, index=False)

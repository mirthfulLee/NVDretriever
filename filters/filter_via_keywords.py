import json

raw_data_json_file = "../result_data/NVD_raw.json"
target_keywords = ["bugzilla", "show_bug.cgi?id="]
result_file = "../result_data/NVD_filtered.json"


if __name__ == "__main__":
    input_f = open(raw_data_json_file, "r", encoding="utf-8")
    output_f = open(result_file, "w", encoding="utf-8")
    cur_line = input_f.readline()[1:]
    first_line = True
    while cur_line:
        matched = True
        for word in target_keywords:
            if word not in cur_line:
                matched = False
                break
        if matched:
            if first_line:
                output_f.write("[")
                first_line = False
            else:
                output_f.write(",\n")

            output_f.write(cur_line)
        cur_line = input_f.readline()[:-2]
    output_f.write("]")
    input_f.close()
    output_f.close()

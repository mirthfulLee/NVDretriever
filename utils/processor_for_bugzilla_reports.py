from allennlp.data import Vocabulary
from allennlp.data.tokenizers import WhitespaceTokenizer, SpacyTokenizer
import re
import sys
import pandas as pd


def replace_tokens_simple(content):
    """process report text line by line"""
    if type(content) != str:
        print("ERROR: not str")
        content = ""
        return content

    # * Attachment TAG
    content = re.sub(r"Created attachment \d+", " ATTACHMENTTAG ", content)

    # * ERROR TAG
    content = re.sub(
        r"\S+?(Error|Exception)([^A-Za-z\s]\S*|\s|$)", " ERRORTAG ", content, flags=re.I
    )

    # * PATH TAG
    # 包含至少两个\或/的token
    content = re.sub(
        r"([/\\][^\s\(\)]+?){2,}[^\s\(\)]*|([^\s\(\)]+?[/\\]){2,}[^\s\(\)]*",
        " PATHTAG ",
        content,
    )

    # * File TAG
    # file type
    file_suffix = "(ml|xml|txt|csv|doc|xls|xlsx|pdf|jar|sh|sbt|zip|gz|tar|7z|rar|exe|bin|dmg|pkg|md|txt|js|c|cc|cpp|dll|a|so|ko|java|py|yml|yaml|conf|log|ini|sys|json|sql|html|css|jsp|php|prod|scss|ts|jpg|png|bmp|gif|mp3|mp4|mpg|mpeg|mov|wav)"
    content = re.sub(r"\s(\S+?\.%s)[?,\.]{0,1}\s" % file_suffix, " FILETAG ", content)

    # * CVE TAG
    # 包含CVE,CWE关键词的token
    content = re.sub(r"CVE-[0-9]+-[0-9]+", " CVETAG ", content, flags=re.I)
    content = re.sub(r"CWE-[0-9]+", " CVETAG ", content, flags=re.I)
    # 包含关键词的url
    content = re.sub(r"https?://\S*(cve|cwe|mitre)\S*", " CVETAG", content, flags=re.I)

    # * URL TAG
    content = re.sub(
        r" http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+ ",
        " URLTAG ",
        content,
    )

    # * EMAIL TAG
    content = re.sub(
        r"[0-9a-zA-Z_]{1,19}@[0-9a-zA-Z\.]{1,19}\.(com|net|cn)",
        " EMAILTAG ",
        content,
    )

    # * API TAG
    # 包含空[]或空()的token
    content = re.sub(r"\S+?((\(\))|(\[\]))\S*", " APITAG ", content)
    # 符合驼峰规则的token
    content = re.sub(r"\S+?([a-z][A-Z]|[A-Z][a-z]{2,}?)\S*", " APITAG ", content)
    # 包含下划线的token
    content = re.sub(r"\S+?_\S+", " APITAG ", content)
    # 包含@（且不是Email）的token
    content = re.sub(r"@\S+", " APITAG ", content)
    # <>包裹的token
    content = re.sub(r"<\S*?>", " APITAG ", content)

    # * TIME TAG
    content = re.sub(
        r"([\s:\-/\.T]\d{1,10}){3,8}(\s*\+?\d+|Z)?",
        " TIMETAG ",
        content,
    )

    # * NUMBER TAG
    content = re.sub(
        r"0x[0-9a-f]+|(?<![g-z])[0-9a-f\-\.]{4,}|[\+\-]?\d+(\.\d*)?",
        " NUMBERTAG ",
        content,
        flags=re.I,
    )
    content = re.sub(
        r"[^a-uwyz:\s]+?\d[^a-uwyz:\s]*(beta[0-9]+)?|beta[0-9]+",
        " NUMBERTAG ",
        content,
        flags=re.I,
    )

    # * AUTHORITY TAG
    # 由 - r w d x 组成的长度为10的token
    content = re.sub(r"[-rwdx]{9,11}", " AUTHORITYTAG ", content, flags=re.I)

    # *低优先级的APITAG规则
    # 包含dot '.'(且不是File, Time, Number)的token
    content = re.sub(r"[^,;\.\s]{3,}?\.\S{4,}", " APITAG ", content)
    # 连续且长度大于30的表达式
    content = re.sub(r"\S{30,}", " APITAG ", content)

    # * LOG TAG
    # 按序分成多行
    lines = content.split("\n")
    content = ""
    logging = False
    # 统计 LOG-word 数量
    for cur in lines:
        total_word_num = len([_ for _ in re.split(r"[,\.;\s/\\:]", cur) if len(_) > 1])
        if total_word_num == 0:
            continue
        log_word_num = len(
            re.findall(
                r"\S+TAG|DEBUG|INFO|WARNING|ERROR|\sin\s|\sat\s", cur, flags=re.I
            )
        )
        valid_word_num = total_word_num - log_word_num
        if (
            (valid_word_num < 3 and log_word_num > 1 and logging)
            or (valid_word_num < 3 and log_word_num > 2)
            or (3 <= valid_word_num < log_word_num / 2)
        ):
            if not logging:
                logging = True
                content = content + " LOGTAG"
        else:
            content = content + " " + cur
            logging = False

    content = re.sub(r"\s{2,}", " ", content)

    return content


def test_via_console():
    # read lines from console; end with EOF(Ctrl+D)
    content = ""
    for line in sys.stdin:
        content = content + line
    print("###########the processed content:###########")
    print(replace_tokens_simple(content))


if __name__ == "__main__":
    test_via_console()

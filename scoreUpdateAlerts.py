import json
import requests
from bs4 import BeautifulSoup
from paddleocr import PaddleOCR
import io
from PIL import Image
import numpy as np
from email.mime.text import MIMEText
from time import sleep
import re
import smtplib

# 配置
username = ''  # 学号
password = ''  # 密码
to_address = ''  # 收件人邮箱
mail_host = ''  # smtp服务器
mail_user = ''  # 发件人邮箱
mail_password = ''  # 邮箱smtp密钥


def captcha(session, retries=5):
    """
    识别验证码
    :param session: web session
    :param retries: 重试次数
    :return: 验证码文本
    """
    for i in range(retries):
        sleep(5)
        ocr = PaddleOCR(use_angle_cls=True, lang="ch", show_log=False)
        captcha_url = "http://jwstudent.lnu.edu.cn/img/captcha.jpg"

        response = session.get(captcha_url)
        image = Image.open(io.BytesIO(response.content))
        # image.save("captcha.jpg")  # 保存验证码图片

        result = ocr.ocr(np.array(image))
        # print("OCR Result:", result)  # 打印完整的OCR结果以进行调试

        if result and len(result) > 0:
            if isinstance(result[0], list) and len(result[0]) > 0:
                if isinstance(result[0][0], list) and len(result[0][0]) > 1:
                    return result[0][0][1]  # 返回识别的文本

        print(f"识别失败第{i + 1}次")

    raise "无法识别验证码"


def login(j_username, j_password, retries=5):
    """
    登录教务系统
    :param j_username: 学号
    :param j_password: 已通过加盐md5加密的密码
    :param retries: 重试次数
    :return: cookie
    """
    for i in range(retries):
        sleep(5)
        session = requests.Session()

        # 获取登录页面
        response = session.get("http://jwstudent.lnu.edu.cn/login")
        soup = BeautifulSoup(response.text, 'html.parser')

        # 获取tokenValue
        token_value = soup.find('input', {'id': 'tokenValue'})['value']

        # 获取并识别验证码
        captcha_code = captcha(session)

        # 准备登录数据
        login_data = {
            'j_username': j_username,
            # 'j_password': hashlib.md5(password.encode()).hexdigest(),
            'j_password': j_password,
            'j_captcha': captcha_code,
            'tokenValue': token_value
        }

        # 发送登录请求
        login_url = "http://jwstudent.lnu.edu.cn/j_spring_security_check"
        response = session.post(login_url, data=login_data)

        if "验证码错误" in response.text:
            print(f"登录失败第{i + 1}次，应该是验证码识别错力")
        elif "错误" in response.text:
            print(f"登录失败第{i + 1}次，应该是用户名密码错误")
        else:
            print("登录成功")
            coo = session.cookies.get_dict()
            return '; '.join(f"{key}={value}" for key, value in coo.items()) + ";"

    raise "登录失败"


def get(url, cookie):
    """
    获取网页数据
    :param url: 网页链接
    :param cookie: cookie
    :return: 网页数据
    """
    sleep(5)
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'Connection': 'keep-alive',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7',
        'Cookie': cookie,
        'referer': 'http://jwstudent.lnu.edu.cn/student/integratedQuery/scoreQuery/thisTermScores/index'
    }
    session = requests.session()
    response = session.get(url, headers=header)
    wbdata = response.text
    return BeautifulSoup(wbdata, 'lxml')


def get_data(cookie):
    """
    获取成绩单数据
    :param cookie: cookie
    :return: 成绩单数据
    """
    url = "http://jwstudent.lnu.edu.cn/student/integratedQuery/scoreQuery/thisTermScores/index"
    html = get(url, cookie)

    regex = r"var\s+url\s*=\s*['\"]([^'\"]*)['\"]"
    match = re.search(regex, str(html))
    if match:
        match_url = 'http://jwstudent.lnu.edu.cn' + match.group(1)
    else:
        raise "链接匹配错误"

    data = str(get(match_url, cookie))
    return data.replace('<html><body><p>', '').replace('</p></body></html>', '')


def show_score(old_score):
    """
    解析成绩单数据
    :param old_score: 成绩单数据
    :return: 解析后的成绩单数据
    """
    try:
        parsed_data = json.loads(old_score)
    except json.JSONDecodeError:
        raise "JSON解析错误"
    for item in parsed_data:
        course_list = item.get("list", [])
        result = ""
        for course in course_list:
            course_name = course.get("courseName")
            course_score = course.get("courseScore")
            result += f"课程: {course_name}, 成绩: {course_score}\n"
        return result


def mail(acc, subject, message, tries=5):
    """
    发送邮件
    :param acc: [smtp服务器，发送邮箱，发送密码，接收邮箱]
    :param subject: 邮件主题
    :param message: 邮件内容
    :param tries: 重试次数
    :return: 无
    """
    for i in range(tries):
        try:
            host, sender, key, receiver = acc[0], acc[1], acc[2], acc[3]
            msg = MIMEText(message, 'plain', _charset="utf-8")
            msg["Subject"] = subject
            with smtplib.SMTP_SSL(host=host, port=465) as smtp:
                smtp.login(user=sender, password=key)
                smtp.sendmail(from_addr=sender, to_addrs=receiver.split(','), msg=msg.as_string())
            print("邮件发送成功")
            return
        except:
            print(f"邮件发送失败第{i + 1}次")

    raise "邮件发送失败"


def encrypt(str_passwd):
    """
    加盐md5加密
    :param str_passwd: 密码
    :return: 加密后的密码
    """

    def md5_rotate_left(l_value, i_shift_bits):
        return (l_value << i_shift_bits) | (l_value >> (32 - i_shift_bits))

    def md5_add_unsigned(l_x, l_y):
        l_x4 = l_x & 0x40000000
        l_y4 = l_y & 0x40000000
        l_x8 = l_x & 0x80000000
        l_y8 = l_y & 0x80000000
        l_result = (l_x & 0x3FFFFFFF) + (l_y & 0x3FFFFFFF)
        if l_x4 & l_y4:
            return l_result ^ 0x80000000 ^ l_x8 ^ l_y8
        if l_x4 | l_y4:
            if l_result & 0x40000000:
                return l_result ^ 0xC0000000 ^ l_x8 ^ l_y8
            else:
                return l_result ^ 0x40000000 ^ l_x8 ^ l_y8
        else:
            return l_result ^ l_x8 ^ l_y8

    def md5_f(x, y, z):
        return (x & y) | (~x & z)

    def md5_g(x, y, z):
        return (x & z) | (y & ~z)

    def md5_h(x, y, z):
        return x ^ y ^ z

    def md5_i(x, y, z):
        return y ^ (x | ~z)

    def md5_ff(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_f(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_gg(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_g(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_hh(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_h(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_ii(a, b, c, d, x, s, ac):
        a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_i(b, c, d), x), ac))
        return md5_add_unsigned(md5_rotate_left(a, s), b)

    def md5_convert_to_word_array(string):
        l_message_length = len(string)
        l_number_of_words_temp1 = l_message_length + 8
        l_number_of_words_temp2 = (l_number_of_words_temp1 - (l_number_of_words_temp1 % 64)) // 64
        l_number_of_words = (l_number_of_words_temp2 + 1) * 16
        l_word_array = [0] * l_number_of_words
        l_byte_position = 0
        l_byte_count = 0

        while l_byte_count < l_message_length:
            l_word_count = l_byte_count // 4
            l_byte_position = (l_byte_count % 4) * 8
            l_word_array[l_word_count] |= ord(string[l_byte_count]) << l_byte_position
            l_byte_count += 1

        l_word_count = l_byte_count // 4
        l_byte_position = (l_byte_count % 4) * 8
        l_word_array[l_word_count] |= 0x80 << l_byte_position
        l_word_array[l_number_of_words - 2] = l_message_length << 3
        l_word_array[l_number_of_words - 1] = l_message_length >> 29

        return l_word_array

    def md5_word_to_hex(l_value):
        word_to_hex_value = ""
        for l_count in range(4):
            l_byte = (l_value >> (l_count * 8)) & 255
            word_to_hex_value += f"{l_byte:02x}"
        return word_to_hex_value

    def md5_utf8_encode(string):
        return string.encode('utf-8')

    def hex_md5(string, ver):
        S11, S12, S13, S14 = 7, 12, 17, 22
        S21, S22, S23, S24 = 5, 9, 14, 20
        S31, S32, S33, S34 = 4, 11, 16, 23
        S41, S42, S43, S44 = 6, 10, 15, 21

        string = md5_utf8_encode(string + ("" if ver == "1.8" else "{Urp602019}")).decode('utf-8')
        x = md5_convert_to_word_array(string)
        a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

        for k in range(0, len(x), 16):
            AA, BB, CC, DD = a, b, c, d

            a = md5_ff(a, b, c, d, x[k + 0], S11, 0xD76AA478)
            d = md5_ff(d, a, b, c, x[k + 1], S12, 0xE8C7B756)
            c = md5_ff(c, d, a, b, x[k + 2], S13, 0x242070DB)
            b = md5_ff(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE)
            a = md5_ff(a, b, c, d, x[k + 4], S11, 0xF57C0FAF)
            d = md5_ff(d, a, b, c, x[k + 5], S12, 0x4787C62A)
            c = md5_ff(c, d, a, b, x[k + 6], S13, 0xA8304613)
            b = md5_ff(b, c, d, a, x[k + 7], S14, 0xFD469501)
            a = md5_ff(a, b, c, d, x[k + 8], S11, 0x698098D8)
            d = md5_ff(d, a, b, c, x[k + 9], S12, 0x8B44F7AF)
            c = md5_ff(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1)
            b = md5_ff(b, c, d, a, x[k + 11], S14, 0x895CD7BE)
            a = md5_ff(a, b, c, d, x[k + 12], S11, 0x6B901122)
            d = md5_ff(d, a, b, c, x[k + 13], S12, 0xFD987193)
            c = md5_ff(c, d, a, b, x[k + 14], S13, 0xA679438E)
            b = md5_ff(b, c, d, a, x[k + 15], S14, 0x49B40821)

            a = md5_gg(a, b, c, d, x[k + 1], S21, 0xF61E2562)
            d = md5_gg(d, a, b, c, x[k + 6], S22, 0xC040B340)
            c = md5_gg(c, d, a, b, x[k + 11], S23, 0x265E5A51)
            b = md5_gg(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA)
            a = md5_gg(a, b, c, d, x[k + 5], S21, 0xD62F105D)
            d = md5_gg(d, a, b, c, x[k + 10], S22, 0x2441453)
            c = md5_gg(c, d, a, b, x[k + 15], S23, 0xD8A1E681)
            b = md5_gg(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8)
            a = md5_gg(a, b, c, d, x[k + 9], S21, 0x21E1CDE6)
            d = md5_gg(d, a, b, c, x[k + 14], S22, 0xC33707D6)
            c = md5_gg(c, d, a, b, x[k + 3], S23, 0xF4D50D87)
            b = md5_gg(b, c, d, a, x[k + 8], S24, 0x455A14ED)
            a = md5_gg(a, b, c, d, x[k + 13], S21, 0xA9E3E905)
            d = md5_gg(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8)
            c = md5_gg(c, d, a, b, x[k + 7], S23, 0x676F02D9)
            b = md5_gg(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A)

            a = md5_hh(a, b, c, d, x[k + 5], S31, 0xFFFA3942)
            d = md5_hh(d, a, b, c, x[k + 8], S32, 0x8771F681)
            c = md5_hh(c, d, a, b, x[k + 11], S33, 0x6D9D6122)
            b = md5_hh(b, c, d, a, x[k + 14], S34, 0xFDE5380C)
            a = md5_hh(a, b, c, d, x[k + 1], S31, 0xA4BEEA44)
            d = md5_hh(d, a, b, c, x[k + 4], S32, 0x4BDECFA9)
            c = md5_hh(c, d, a, b, x[k + 7], S33, 0xF6BB4B60)
            b = md5_hh(b, c, d, a, x[k + 10], S34, 0xBEBFBC70)
            a = md5_hh(a, b, c, d, x[k + 13], S31, 0x289B7EC6)
            d = md5_hh(d, a, b, c, x[k + 0], S32, 0xEAA127FA)
            c = md5_hh(c, d, a, b, x[k + 3], S33, 0xD4EF3085)
            b = md5_hh(b, c, d, a, x[k + 6], S34, 0x4881D05)
            a = md5_hh(a, b, c, d, x[k + 9], S31, 0xD9D4D039)
            d = md5_hh(d, a, b, c, x[k + 12], S32, 0xE6DB99E5)
            c = md5_hh(c, d, a, b, x[k + 15], S33, 0x1FA27CF8)
            b = md5_hh(b, c, d, a, x[k + 2], S34, 0xC4AC5665)

            a = md5_ii(a, b, c, d, x[k + 0], S41, 0xF4292244)
            d = md5_ii(d, a, b, c, x[k + 7], S42, 0x432AFF97)
            c = md5_ii(c, d, a, b, x[k + 14], S43, 0xAB9423A7)
            b = md5_ii(b, c, d, a, x[k + 5], S44, 0xFC93A039)
            a = md5_ii(a, b, c, d, x[k + 12], S41, 0x655B59C3)
            d = md5_ii(d, a, b, c, x[k + 3], S42, 0x8F0CCC92)
            c = md5_ii(c, d, a, b, x[k + 10], S43, 0xFFEFF47D)
            b = md5_ii(b, c, d, a, x[k + 1], S44, 0x85845DD1)
            a = md5_ii(a, b, c, d, x[k + 8], S41, 0x6FA87E4F)
            d = md5_ii(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0)
            c = md5_ii(c, d, a, b, x[k + 6], S43, 0xA3014314)
            b = md5_ii(b, c, d, a, x[k + 13], S44, 0x4E0811A1)
            a = md5_ii(a, b, c, d, x[k + 4], S41, 0xF7537E82)
            d = md5_ii(d, a, b, c, x[k + 11], S42, 0xBD3AF235)
            c = md5_ii(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB)
            b = md5_ii(b, c, d, a, x[k + 9], S44, 0xEB86D391)

            a = md5_add_unsigned(a, AA)
            b = md5_add_unsigned(b, BB)
            c = md5_add_unsigned(c, CC)
            d = md5_add_unsigned(d, DD)

        return (md5_word_to_hex(a) + md5_word_to_hex(b) + md5_word_to_hex(c) + md5_word_to_hex(d)).lower()


    return hex_md5(str_passwd, '')


if __name__ == '__main__':
    # 检测信息是否有误
    mail_info = [mail_host, mail_user, mail_password, to_address]
    try:
        password = encrypt(password)
        cookies = login(username, password)
        score = get_data(cookies)
        print(show_score(score))
        mail(mail_info, "监控程序开始运行", show_score(score))
    except:
        mail(mail_info, "信息填充有误，请重新确认", "信息填充有误，请重新确认")
        raise "信息填充有误，请重新确认"

    # 循环监测
    for j in range(10):
        cookies = login(username, password)
        score = get_data(cookies)
        try:
            while True:
                new_score = get_data(cookies)
                if new_score != score:
                    score = new_score
                    print("更新成功\n" + show_score(new_score))
                    mail(mail_info, "更新成功！请进入教务系统查看最新成绩单\n", show_score(new_score))
                else:
                    print("无更新")
                    sleep(60)
        except:
            print(f"未知错误，大概率是cookie失效了，此为第{j + 1}/10个cookie")
            mail(mail_info, f"未知错误，大概率是cookie失效了，此为第{j + 1}/10个cookie")

    print("监控程序结束")

import re
import pandas as pd
import json
from collections import Counter


def parse_hwo_file(file_path):
    """
    解析危险天气展望文件，提取结构化信息
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # 按记录分隔符分割
    entries = content.split('\n')[1:]
    parsed_data = []
    
    for i, entry in enumerate(entries):
        if not entry.strip():
            continue
            
        lines = entry.strip().split('\n')
        if len(lines) < 5:
            continue
        
        try:
            # 提取基础信息
            record_info = extract_basic_info(lines, i)
            
            # 提取详细内容
            detailed_info = extract_detailed_content(lines)
            
            # 合并信息
            record_data = {**record_info, **detailed_info}
            parsed_data.append(record_data)
            
        except Exception as e:
            print(f"解析第 {i+1} 条记录时出错: {e}")
            continue
    
    return parsed_data

def extract_basic_info(lines, record_num):
    """提取基础信息"""
    info = {'record_id': record_num + 1}
    
    # 提取文件头信息
    if lines:
        header = lines[0]
        info['byte_count'] = header.strip() if header and header.strip().isdigit() else None
    
    # 提取发布时间 - 修复的时间提取逻辑
    info['issue_time'] = extract_issue_time_improved(lines)
    
    # 提取预警类型
    info['alert_type'] = 'UNKNOWN'
    for line in lines[:10]:
        if 'HAZARDOUS WEATHER OUTLOOK' in line:
            info['alert_type'] = 'HAZARDOUS_WEATHER_OUTLOOK'
            break
    
    # 提取区域代码和名称
    area_codes = []
    area_names = []
    for line in lines:
        line = line.strip()
        # 区域代码模式
        if re.match(r'^[A-Z]+\d+[\->\d,]*-\d{6}-', line):
            area_codes.append(line)
        # 区域名称模式 - 更精确的匹配
        elif re.match(r'^[A-Z]+(-[A-Z]+)*,?$', line) and len(line) < 100:
            area_names.append(line)
    
    info['area_codes'] = area_codes if area_codes else []
    info['area_names'] = area_names if area_names else []
    
    return info

def extract_issue_time_improved(lines):
    """改进的时间提取函数，支持大小写混合的月份和星期"""
    for line in lines[:15]:
        line = line.strip()
        # 通用匹配模式
        pattern = r'(\d{1,4}\s[APM]{2}\s\w+\s\w+\s\w+\s\d{1,2}\s\d{4})'
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return 'Unknown'


def extract_detailed_content(lines):
    """
    提取详细内容部分，改进 day_one 截断问题
    - 宽松匹配章节标题
    - 保留所有正文行
    - 拼接折行文本，不截断单词
    """
    content = {
        'day_one': '',
        'days_two_seven': '',
        'spotter_info': '',
        'coastal_waters': False,
        'hazard_types': [],
        'advisories': []
    }

    current_section = None
    coastal_section = False
    buffer = ''

    for line in lines:
        raw_line = line.rstrip('\n').strip()

        # 跳过空行
        if not raw_line:
            continue

        # 检查是否是海域部分
        if any(keyword in raw_line.upper() for keyword in ['COASTAL WATERS', 'GALVESTON BAY', 'MATAGORDA BAY', 'WATERS FROM']):
            coastal_section = True
            content['coastal_waters'] = True

        # 宽松匹配章节标题，不区分大小写
        if re.search(r'\.DAY ONE\.+', raw_line, re.IGNORECASE):
            current_section = 'day_one'
            buffer = ''
            continue
        elif re.search(r'\.DAYS TWO THROUGH SEVEN\.+', raw_line, re.IGNORECASE):
            if current_section and buffer:
                content[current_section] = buffer.strip()
            current_section = 'days_two_seven'
            buffer = ''
            continue
        elif re.search(r'\.SPOTTER INFORMATION STATEMENT\.+', raw_line, re.IGNORECASE):
            if current_section and buffer:
                content[current_section] = buffer.strip()
            current_section = 'spotter_info'
            buffer = ''
            continue
        elif raw_line == '$$' or raw_line == '':
            if current_section and buffer:
                content[current_section] = buffer.strip()
            current_section = None
            buffer = ''
            coastal_section = False
            continue

        # 拼接当前章节文本
        if current_section:
            if buffer:
                # 如果上一行没有以句号结束，直接拼接
                if not buffer.endswith(('.', '!', '?')):
                    buffer += ' ' + raw_line
                else:
                    buffer += ' ' + raw_line
            else:
                buffer = raw_line

    # 保存最后一个章节
    if current_section and buffer:
        content[current_section] = buffer.strip()

    # 提取危险天气类型和预警
    content['hazard_types'] = extract_hazard_types(content)
    content['advisories'] = extract_advisories(content)

    return content

def extract_hazard_types(content):
    """提取危险天气类型"""
    hazards = []
    text = ' '.join([content['day_one'], content['days_two_seven']]).upper()
    
    hazard_keywords = {
        'FOG': ['FOG', 'DENSE FOG'],
        'WIND': ['WIND', 'GUST', 'GALE'],
        'FREEZE': ['FREEZING', 'FREEZE', 'FROST'],
        'FLOOD': ['FLOOD', 'RAINFALL', 'HEAVY RAIN'],
        'THUNDERSTORM': ['THUNDERSTORM', 'LIGHTNING'],
        'TORNADO': ['TORNADO', 'FUNNEL'],
        'COLD': ['COLD', 'WIND CHILL'],
        'COASTAL': ['COASTAL FLOOD', 'TIDE', 'RIP CURRENT'],
        'RAIN': ['RAIN', 'SHOWER', 'PRECIPITATION']
    }
    
    for hazard_type, keywords in hazard_keywords.items():
        for keyword in keywords:
            if keyword in text:
                hazards.append(hazard_type)
                break
    
    return list(set(hazards))

def extract_advisories(content):
    """提取预警类型"""
    advisories = []
    text = ' '.join([content['day_one'], content['days_two_seven']]).upper()
    
    advisory_keywords = {
        'WIND_ADVISORY': ['WIND ADVISORY'],
        'FREEZE_WARNING': ['FREEZE WARNING'],
        'FLOOD_WATCH': ['FLASH FLOOD WATCH', 'FLOOD WATCH'],
        'DENSE_FOG_ADVISORY': ['DENSE FOG ADVISORY'],
        'SMALL_CRAFT_ADVISORY': ['SMALL CRAFT ADVISORY'],
        'GALE_WARNING': ['GALE WARNING'],
        'HARD_FREEZE_WARNING': ['HARD FREEZE WARNING'],
        'COASTAL_FLOOD_ADVISORY': ['COASTAL FLOOD ADVISORY']
    }
    
    for advisory_type, keywords in advisory_keywords.items():
        for keyword in keywords:
            if keyword in text:
                advisories.append(advisory_type)
                break
    
    return advisories

def save_data(parsed_data):
    """保存数据到多个格式"""
    if not parsed_data:
        print("没有数据可保存")
        return
    
    # 创建DataFrame
    df = pd.DataFrame(parsed_data)
    
    print(f"成功创建DataFrame，包含 {len(df)} 条记录")
    print(f"列名: {df.columns.tolist()}")
    
    # 处理列表类型的列
    for col in ['area_codes', 'area_names', 'hazard_types', 'advisories']:
        if col in df.columns:
            df[f'{col}_str'] = df[col].apply(
                lambda x: '; '.join(x) if isinstance(x, list) and x else ''
            )
    
    # 1. 保存为CSV
    csv_file = "./data/weather_outlook_analysis.csv"
    df.to_csv(csv_file, index=False, encoding='utf-8')
    print(f"CSV文件已保存: {csv_file}")
    
    # 2. 保存为JSON
    json_file = "./data/weather_outlook_analysis.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        # 转换列表为字符串以便JSON序列化
        json_data = []
        for record in parsed_data:
            json_record = {}
            for key, value in record.items():
                if isinstance(value, list):
                    json_record[key] = value
                else:
                    json_record[key] = str(value) if value is not None else ""
            json_data.append(json_record)
        
        json.dump(json_data, f, ensure_ascii=False, indent=2)
    print(f"JSON文件已保存: {json_file}")
    
    # 3. 保存简化的文本报告
    txt_file = "./data/weather_summary.txt"
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write("气象预警数据汇总报告\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"总记录数: {len(parsed_data)}\n\n")
        
        # 统计信息
        hazard_counts = Counter()
        advisory_counts = Counter()
        coastal_count = 0
        
        for record in parsed_data:
            if record.get('coastal_waters'):
                coastal_count += 1
            for hazard in record.get('hazard_types', []):
                hazard_counts[hazard] += 1
            for advisory in record.get('advisories', []):
                advisory_counts[advisory] += 1
        
        f.write("危险天气类型统计:\n")
        for hazard, count in hazard_counts.most_common():
            percentage = (count / len(parsed_data)) * 100
            f.write(f"  {hazard}: {count}次 ({percentage:.1f}%)\n")
        
        f.write(f"\n海域预警数量: {coastal_count}次\n")
        
        if advisory_counts:
            f.write("\n预警类型分布:\n")
            for advisory, count in advisory_counts.most_common():
                f.write(f"  {advisory}: {count}次\n")
    
    print(f"文本报告已保存: {txt_file}")
    
    return df

def generate_detailed_analysis(parsed_data):
    """生成详细分析报告"""
    analysis_file = "./data/detailed_analysis.txt"
    
    with open(analysis_file, 'w', encoding='utf-8') as f:
        f.write("详细气象预警分析报告\n")
        f.write("=" * 50 + "\n\n")
        
        monthly_data = {}
        valid_time_records = [r for r in parsed_data if r.get('issue_time') != 'Unknown']
        
        f.write(f"有效时间记录: {len(valid_time_records)}/{len(parsed_data)}\n\n")
        
        for record in valid_time_records:
            issue_time = record.get('issue_time', '')
            # 提取月份
            month_match = re.search(r'([A-Z]{3}) \d{1,2} \d{4}', issue_time)
            if month_match:
                month = month_match.group(1)
                if month not in monthly_data:
                    monthly_data[month] = 0
                monthly_data[month] += 1
        
        f.write("月度分布:\n")
        for month, count in sorted(monthly_data.items()):
            f.write(f"  {month}: {count}条记录\n")
        
        coastal_hazards = Counter()
        inland_hazards = Counter()
        
        for record in parsed_data:
            hazards = record.get('hazard_types', [])
            if record.get('coastal_waters'):
                for hazard in hazards:
                    coastal_hazards[hazard] += 1
            else:
                for hazard in hazards:
                    inland_hazards[hazard] += 1
        
        f.write("\n海域预警危险类型:\n")
        for hazard, count in coastal_hazards.most_common():
            f.write(f"  {hazard}: {count}次\n")
        
        f.write("\n陆地预警危险类型:\n")
        for hazard, count in inland_hazards.most_common():
            f.write(f"  {hazard}: {count}次\n")

    print(f"详细分析报告已保存: {analysis_file}")

def analyze_time_extraction(parsed_data):
    """分析时间提取效果"""
    total_records = len(parsed_data)
    valid_time_records = sum(1 for r in parsed_data if r.get('issue_time') != 'Unknown')
    
    print(f"\n时间提取分析:")
    print(f"总记录数: {total_records}")
    print(f"成功提取时间: {valid_time_records}")
    print(f"提取成功率: {valid_time_records/total_records*100:.1f}%")
    
    if valid_time_records > 0:
        print("\n前5个成功提取的时间示例:")
        count = 0
        for record in parsed_data:
            if record.get('issue_time') != 'Unknown' and count < 5:
                print(f"  记录 {record['record_id']}: {record['issue_time']}")
                count += 1

if __name__ == "__main__":
    file_path = "./data/base/warning_information_HOUSTON.txt"
    
    print("开始解析文件...")
    parsed_data = parse_hwo_file(file_path)
    
    if not parsed_data:
        print("没有成功解析任何记录")
        exit()
    
    print(f"成功解析 {len(parsed_data)} 条记录")
    
    analyze_time_extraction(parsed_data)
    
    print("\n解析结果统计:")
    hazard_counts = Counter()
    for record in parsed_data:
        for hazard in record.get('hazard_types', []):
            hazard_counts[hazard] += 1
    
    for hazard, count in hazard_counts.most_common():
        percentage = (count / len(parsed_data)) * 100
        print(f"  {hazard}: {count}次 ({percentage:.1f}%)")
    
    df = save_data(parsed_data)
    
    # 分析
    generate_detailed_analysis(parsed_data)
    
    print("\n" + "="*50)
    print("处理完成！生成的文件:")
    print("  - weather_outlook_analysis.csv (主要数据)")
    print("  - weather_outlook_analysis.json (JSON格式)")
    print("  - weather_summary.txt (统计摘要)")
    print("  - detailed_analysis.txt (详细分析)")
    print("="*50)
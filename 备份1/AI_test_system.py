from dataclasses import dataclass, field
from typing import List, Dict, Optional
import datetime
from random import sample, choice, shuffle
import time
from collections import Counter
import json
# 移除可能导致ModuleNotFoundError的依赖
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.metrics.pairwise import cosine_similarity
# import numpy as np

@dataclass
class Question:
    qid: str
    knowledge_point: str
    difficulty: str
    qtype: str
    content: str
    answer: str
    options: Optional[Dict[str, str]] = None
    score_std: Optional[str] = None
    source: str = "ai_generated"

@dataclass
class AnswerRecord:
    sid: str
    qid: str
    test_id: str
    student_answer: str
    is_correct: Optional[bool] = None
    score: Optional[float] = None
    spend_time: float = 0.0
    submit_time: datetime.datetime = field(default_factory=datetime.datetime.now)

@dataclass
class TestConfig:
    test_id: str
    knowledge_points: List[str]
    difficulty: str
    qtype_counts: Dict[str, int]
    time_limit: int = 30
    anti_cheat: bool = True

class MockAIService:
    """模拟AI服务，替代OpenAI API调用"""
    
    @staticmethod
    def generate_questions_prompt(config: TestConfig) -> str:
        """生成题目提示词"""
        return f"""请生成{config.difficulty}难度的{','.join(config.knowledge_points)}相关题目"""
    
    @staticmethod
    def analyze_error_pattern(knowledge_point: str) -> str:
        """分析错误模式"""
        analysis_map = {
            "Python基础": "Python基础语法掌握不牢固，需要加强变量、函数、类的理解",
            "算法": "算法思维需要训练，重点理解时间复杂度和常用算法模式",
            "数据库": "SQL语法和数据库概念需要巩固",
            "网络": "网络协议和通信原理需要深入理解"
        }
        return analysis_map.get(knowledge_point, "该知识点需要加强练习和理解")

class AIQuestionGenerator: 
    def __init__(self, model: str = "mock-model"):
        self.model = model
        self.question_bank: List[Question] = []
        self._init_sample_questions()
        self.question_types = ["single", "multiple", "judge", "short", "discussion"]  # 新增论述题类型

    def _init_sample_questions(self):
        """初始化示例题目库"""
        sample_questions = [
            # 计算机相关题目
            Question(
                qid="single_01", 
                knowledge_point="Python基础", 
                difficulty="中等", 
                qtype="single", 
                content="Python中定义函数用哪个关键字？", 
                options={"A": "def", "B": "class", "C": "import", "D": "print"}, 
                answer="A"
            ),
            Question(
                qid="multiple_01", 
                knowledge_point="算法", 
                difficulty="中等", 
                qtype="multiple", 
                content="以下属于排序算法的是？", 
                options={"A": "冒泡排序", "B": "二分查找", "C": "快速排序", "D": "哈希表"}, 
                answer="A,C"
            ),
            Question(
                qid="judge_01", 
                knowledge_point="数据库", 
                difficulty="中等", 
                qtype="judge", 
                content="SQL中SELECT用于查询数据？", 
                options={"A": "正确", "B": "错误"}, 
                answer="A"
            ),
            Question(
                qid="short_01", 
                knowledge_point="网络", 
                difficulty="中等", 
                qtype="short", 
                content="简述HTTP协议的特点", 
                answer="无状态、基于请求响应、应用层协议",
                score_std="答出无状态得3分，完整得5分"
            ),
            Question(
                qid="single_02", 
                knowledge_point="Python基础", 
                difficulty="简单", 
                qtype="single", 
                content="Python中打印输出用哪个函数？", 
                options={"A": "print", "B": "echo", "C": "log", "D": "output"}, 
                answer="A"
            ),
            
            # 数学相关题目
            Question(
                qid="single_math_01", 
                knowledge_point="数学", 
                difficulty="简单", 
                qtype="single", 
                content="以下哪个是质数？", 
                options={"A": "8", "B": "9", "C": "11", "D": "12"}, 
                answer="C"
            ),
            Question(
                qid="multiple_math_01", 
                knowledge_point="数学", 
                difficulty="中等", 
                qtype="multiple", 
                content="以下哪些是直角三角形的边长？", 
                options={"A": "3,4,5", "B": "5,12,13", "C": "6,8,10", "D": "7,8,9"}, 
                answer="A,B,C"
            ),
            Question(
                qid="judge_math_01", 
                knowledge_point="数学", 
                difficulty="简单", 
                qtype="judge", 
                content="圆的周长公式是2πr？", 
                options={"A": "正确", "B": "错误"}, 
                answer="A"
            ),
            Question(
                qid="short_math_01", 
                knowledge_point="数学", 
                difficulty="中等", 
                qtype="short", 
                content="简述二次函数的图像性质", 
                answer="二次函数图像是抛物线，当a>0时开口向上，有最小值；当a<0时开口向下，有最大值；对称轴为x=-b/(2a)",
                score_std="答出抛物线得2分，开口方向得3分，对称轴得3分，完整得8分"
            ),
            
            # 英语相关题目
            Question(
                qid="single_english_01", 
                knowledge_point="英语", 
                difficulty="简单", 
                qtype="single", 
                content="'Apple'的中文意思是？", 
                options={"A": "香蕉", "B": "苹果", "C": "橙子", "D": "梨子"}, 
                answer="B"
            ),
            Question(
                qid="multiple_english_01", 
                knowledge_point="英语", 
                difficulty="中等", 
                qtype="multiple", 
                content="以下哪些是形容词？", 
                options={"A": "happy", "B": "run", "C": "beautiful", "D": "quickly"}, 
                answer="A,C"
            ),
            Question(
                qid="judge_english_01", 
                knowledge_point="英语", 
                difficulty="简单", 
                qtype="judge", 
                content="'He'是第三人称单数代词？", 
                options={"A": "正确", "B": "错误"}, 
                answer="A"
            ),
            Question(
                qid="short_english_01", 
                knowledge_point="英语", 
                difficulty="中等", 
                qtype="short", 
                content="简述一般现在时的用法", 
                answer="一般现在时用于表示经常性或习惯性的动作、客观事实或普遍真理、现在的状态或特征",
                score_std="答出经常性动作得3分，客观事实得3分，现在状态得2分，完整得8分"
            ),
            
            # 物理相关题目
            Question(
                qid="single_physics_01", 
                knowledge_point="物理", 
                difficulty="简单", 
                qtype="single", 
                content="以下哪个是力的单位？", 
                options={"A": "焦耳", "B": "牛顿", "C": "瓦特", "D": "欧姆"}, 
                answer="B"
            ),
            Question(
                qid="multiple_physics_01", 
                knowledge_point="物理", 
                difficulty="中等", 
                qtype="multiple", 
                content="以下哪些是力学基本定律？", 
                options={"A": "牛顿第一定律", "B": "欧姆定律", "C": "牛顿第二定律", "D": "法拉第定律"}, 
                answer="A,C"
            ),
            Question(
                qid="judge_physics_01", 
                knowledge_point="物理", 
                difficulty="简单", 
                qtype="judge", 
                content="重力的方向总是竖直向下？", 
                options={"A": "正确", "B": "错误"}, 
                answer="A"
            ),
            
            # 化学相关题目
            Question(
                qid="single_chemistry_01", 
                knowledge_point="化学", 
                difficulty="简单", 
                qtype="single", 
                content="水的化学式是？", 
                options={"A": "H2O", "B": "CO2", "C": "O2", "D": "H2"}, 
                answer="A"
            ),
            Question(
                qid="judge_chemistry_01", 
                knowledge_point="化学", 
                difficulty="简单", 
                qtype="judge", 
                content="氧气是可燃气体？", 
                options={"A": "正确", "B": "错误"}, 
                answer="B"
            ),
            
            # 历史相关题目
            Question(
                qid="single_history_01", 
                knowledge_point="历史", 
                difficulty="中等", 
                qtype="single", 
                content="中国第一个统一的封建王朝是？", 
                options={"A": "商朝", "B": "周朝", "C": "秦朝", "D": "汉朝"}, 
                answer="C"
            ),
            Question(
                qid="judge_history_01", 
                knowledge_point="历史", 
                difficulty="简单", 
                qtype="judge", 
                content="鸦片战争发生在1840年？", 
                options={"A": "正确", "B": "错误"}, 
                answer="A"
            ),
            
            # 地理相关题目
            Question(
                qid="single_geography_01", 
                knowledge_point="地理", 
                difficulty="简单", 
                qtype="single", 
                content="地球自转一周的时间是？", 
                options={"A": "一天", "B": "一个月", "C": "一年", "D": "一个世纪"}, 
                answer="A"
            ),
            Question(
                qid="multiple_geography_01", 
                knowledge_point="地理", 
                difficulty="中等", 
                qtype="multiple", 
                content="以下哪些是七大洲？", 
                options={"A": "亚洲", "B": "非洲", "C": "大洋洲", "D": "地中海"}, 
                answer="A,B,C"
            )
        ]
        self.question_bank.extend(sample_questions)

    def get_from_bank(self, config: TestConfig) -> List[Question]:
        """从题库中选取题目"""
        # 确保配置和知识点不为空
        if not hasattr(config, 'knowledge_points') or not config.knowledge_points:
            config_knowledge_points = ['Python基础']
        else:
            config_knowledge_points = config.knowledge_points
            
        # 确保qtype_counts不为空
        if not hasattr(config, 'qtype_counts') or not config.qtype_counts:
            config_qtype_counts = {'single': 2, 'multiple': 1, 'judge': 1, 'short': 1}
        else:
            config_qtype_counts = config.qtype_counts
        
        # 放宽匹配条件：只要题目知识点包含在配置的知识点中即可，难度可以不严格匹配
        candidates = [q for q in self.question_bank
                    if any(kp in q.knowledge_point for kp in config_knowledge_points)]
        
        # 如果没有匹配到题目，使用所有题库题目
        if not candidates:
            candidates = self.question_bank
        
        selected = []
        for qtype, count in config_qtype_counts.items():
            type_candidates = [q for q in candidates if q.qtype == qtype]
            if len(type_candidates) >= count:
                selected.extend(sample(type_candidates, count))
            else:
                selected.extend(type_candidates)
        return selected

    def generate_ai_questions(self, config: TestConfig) -> List[Question]:
        """AI生成题目或从题库选取"""
        print("AI生成/选取题目...")
        
        # 确保配置和qtype_counts不为空
        if not hasattr(config, 'qtype_counts') or not config.qtype_counts:
            config.qtype_counts = {'single': 2, 'multiple': 1, 'judge': 1, 'short': 1}
        
        # 首先从题库中选取题目
        bank_questions = self.get_from_bank(config)
        
        # 如果题库中的题目不足，生成新题目
        generated_questions = []
        for qtype, count in config.qtype_counts.items():
            existing_count = sum(1 for q in bank_questions if q.qtype == qtype)
            if existing_count < count:
                # 生成缺失的题目
                missing_count = count - existing_count
                generated = self._generate_new_questions(config, qtype, missing_count)
                generated_questions.extend(generated)
        
        # 合并题目并打乱顺序
        all_questions = bank_questions + generated_questions
        
        # 确保至少返回一些题目，避免空列表
        if not all_questions:
            # 使用默认题目
            default_questions = self._generate_new_questions(config, 'single', 5)
            all_questions = default_questions
        
        shuffle(all_questions)
        return all_questions

    def _generate_new_questions(self, config: TestConfig, qtype: str, count: int) -> List[Question]:
        """生成新题目"""
        new_questions = []
        for i in range(count):
            # 模拟AI生成题目
            knowledge_point = choice(config.knowledge_points)
            qid = f"{qtype}_{int(time.time())}_{i}"
            
            if qtype == "single":
                content = f"{knowledge_point}单选题示例{i+1}"
                options = {"A": "选项A", "B": "选项B", "C": "选项C", "D": "选项D"}
                answer = choice(["A", "B", "C", "D"])
                question = Question(
                    qid=qid,
                    knowledge_point=knowledge_point,
                    difficulty=config.difficulty,
                    qtype=qtype,
                    content=content,
                    answer=answer,
                    options=options
                )
                new_questions.append(question)
            elif qtype == "multiple":
                content = f"{knowledge_point}多选题示例{i+1}"
                options = {"A": "选项A", "B": "选项B", "C": "选项C", "D": "选项D"}
                # 随机生成2-4个正确答案
                correct_count = choice(range(2, 5))
                answer = ",".join(sample(["A", "B", "C", "D"], correct_count))
                question = Question(
                    qid=qid,
                    knowledge_point=knowledge_point,
                    difficulty=config.difficulty,
                    qtype=qtype,
                    content=content,
                    answer=answer,
                    options=options
                )
                new_questions.append(question)
            elif qtype == "judge":
                content = f"{knowledge_point}判断题示例{i+1}"
                options = {"A": "正确", "B": "错误"}
                answer = choice(["A", "B"])
                question = Question(
                    qid=qid,
                    knowledge_point=knowledge_point,
                    difficulty=config.difficulty,
                    qtype=qtype,
                    content=content,
                    answer=answer,
                    options=options
                )
                new_questions.append(question)
            elif qtype == "short":
                content = f"{knowledge_point}简答题示例{i+1}"
                answer = f"{knowledge_point}相关答案示例，包含核心知识点和关键要点"
                score_std = "根据回答完整性和准确性评分，核心知识点占60%，关键点占40%"
                question = Question(
                    qid=qid,
                    knowledge_point=knowledge_point,
                    difficulty=config.difficulty,
                    qtype=qtype,
                    content=content,
                    answer=answer,
                    score_std=score_std
                )
                new_questions.append(question)
            elif qtype == "discussion":  # 新增论述题类型
                content = f"{knowledge_point}论述题示例{i+1}：请详细论述其原理、应用场景及优缺点"
                answer = f"{knowledge_point}的原理是...，主要应用场景包括...，其优点是...，缺点是...，未来发展趋势是..."
                score_std = "根据论述完整性(30%)、逻辑清晰度(25%)、案例支持(20%)、深度和广度(25%)评分"
                question = Question(
                    qid=qid,
                    knowledge_point=knowledge_point,
                    difficulty=config.difficulty,
                    qtype=qtype,
                    content=content,
                    answer=answer,
                    score_std=score_std
                )
                new_questions.append(question)
        
        return new_questions

    def add_to_bank(self, question: Question):
        self.question_bank.append(question)
        
    def get_question_by_id(self, qid: str) -> Optional[Question]:
        """根据题目ID获取题目"""
        for q in self.question_bank:
            if q.qid == qid:
                return q
        return None

class OnlineTestManager:
    def __init__(self):
        self.test_sessions: Dict[str, Dict[str, Dict]] = {}
        self.anti_cheat_settings = {
            "max_cheat_count": 3,
            "screen_switch_detection": True,
            "camera_monitoring": True,
            "tab_switch_detection": True,
            "inactivity_threshold": 300,  # 5分钟无活动视为作弊
            "multiple_devices_detection": True
        }

    def start_test(self, sid: str, test_id: str, config: TestConfig) -> Dict:
        """开始测验"""
        start_time = time.time()
        end_time = start_time + config.time_limit * 60
        self.test_sessions.setdefault(test_id, {})[sid] = {
            "start_time": start_time,
            "end_time": end_time,
            "cheat_count": 0,
            "is_timeout": False,
            "answers": [],
            "current_diff": config.difficulty,
            "screen_switches": 0,
            "tab_switches": 0,
            "camera_status": "active",
            "last_activity_time": start_time,
            "device_info": "",
            "inactivity_warnings": 0,
            "is_cheating": False
        }
        return {"status": "success", "test_id": test_id, "end_time": end_time, "start_time": start_time}

    def submit_answer(self, sid: str, test_id: str, record: AnswerRecord) -> Dict:
        """提交答案"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "测验会话不存在"}
        
        # 检查超时
        if time.time() > session["end_time"]:
            session["is_timeout"] = True
            return {"status": "error", "msg": "测验已超时"}
        
        # 更新最后活动时间
        session["last_activity_time"] = time.time()
        
        # 检测作弊
        cheat_result = self._detect_cheat(sid, test_id)
        if cheat_result["is_cheat"]:
            session["cheat_count"] += 1
            if session["cheat_count"] >= self.anti_cheat_settings["max_cheat_count"]:
                session["is_cheating"] = True
                return {"status": "error", "msg": "作弊次数过多，测验终止", "cheat_type": cheat_result["cheat_type"]}
        
        # 记录答案
        session["answers"].append(record)
        return {"status": "success", "cheat_count": session["cheat_count"], "remaining_time": max(0, int(session["end_time"] - time.time()))}

    def end_test(self, sid: str, test_id: str) -> Dict:
        """结束测验"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        # 计算总分
        total_score = sum(ans.score for ans in session["answers"] if ans.score is not None)
        return {"status": "success", "answer_count": len(session["answers"]), "total_score": total_score, "cheat_count": session["cheat_count"], "is_cheating": session["is_cheating"]}

    def get_session(self, sid: str, test_id: str) -> Optional[Dict]:
        """获取会话信息"""
        return self.test_sessions.get(test_id, {}).get(sid)

    def _detect_cheat(self, sid: str, test_id: str) -> Dict:
        """检测作弊行为"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"is_cheat": False, "cheat_type": None}
        
        # 检测无活动时间
        if time.time() - session["last_activity_time"] > self.anti_cheat_settings["inactivity_threshold"]:
            session["inactivity_warnings"] += 1
            return {"is_cheat": True, "cheat_type": "inactivity"}
        
        # 模拟其他作弊检测结果（实际应用中应使用真实的检测逻辑）
        cheat_types = [
            "screen_switch", "tab_switch", "camera_off", "multiple_devices"
        ]
        
        # 随机生成作弊检测结果（实际应用中应使用真实的检测逻辑）
        if choice([True, False, False, False, False]):
            cheat_type = choice(cheat_types)
            if cheat_type == "screen_switch":
                session["screen_switches"] += 1
            elif cheat_type == "tab_switch":
                session["tab_switches"] += 1
            elif cheat_type == "camera_off":
                session["camera_status"] = "inactive"
            
            return {"is_cheat": True, "cheat_type": cheat_type}
        
        return {"is_cheat": False, "cheat_type": None}

    def update_cheat_status(self, sid: str, test_id: str, cheat_type: str) -> Dict:
        """更新作弊状态"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        session["cheat_count"] += 1
        if cheat_type == "screen_switch":
            session["screen_switches"] += 1
        elif cheat_type == "tab_switch":
            session["tab_switches"] += 1
        elif cheat_type == "camera_off":
            session["camera_status"] = "inactive"
        elif cheat_type == "inactivity":
            session["inactivity_warnings"] += 1
        
        if session["cheat_count"] >= self.anti_cheat_settings["max_cheat_count"]:
            session["is_cheating"] = True
            return {"status": "error", "msg": "作弊次数过多，测验终止", "cheat_count": session["cheat_count"]}
        
        return {"status": "warning", "msg": f"检测到{cheat_type}行为", "cheat_count": session["cheat_count"], "max_cheat_count": self.anti_cheat_settings["max_cheat_count"]}

    def get_remaining_time(self, sid: str, test_id: str) -> int:
        """获取剩余时间"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return 0
        return max(0, int(session["end_time"] - time.time()))

    def check_timeout(self, sid: str, test_id: str) -> bool:
        """检查是否超时"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return True
        return time.time() > session["end_time"]

    def update_activity_time(self, sid: str, test_id: str) -> Dict:
        """更新活动时间"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        session["last_activity_time"] = time.time()
        return {"status": "success"}

    def check_inactivity(self, sid: str, test_id: str) -> Dict:
        """检查无活动情况"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        inactivity_time = time.time() - session["last_activity_time"]
        if inactivity_time > self.anti_cheat_settings["inactivity_threshold"]:
            return {"status": "warning", "msg": f"已超过{int(inactivity_time/60)}分钟无活动，请继续答题", "inactivity_time": inactivity_time}
        
        return {"status": "success", "inactivity_time": inactivity_time}

    def update_device_info(self, sid: str, test_id: str, device_info: str) -> Dict:
        """更新设备信息"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        # 简单的多设备检测逻辑
        if session["device_info"] and session["device_info"] != device_info:
            return self.update_cheat_status(sid, test_id, "multiple_devices")
        
        session["device_info"] = device_info
        return {"status": "success"}

    def get_cheat_report(self, sid: str, test_id: str) -> Dict:
        """获取作弊报告"""
        session = self.test_sessions.get(test_id, {}).get(sid)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        return {
            "cheat_count": session["cheat_count"],
            "screen_switches": session["screen_switches"],
            "tab_switches": session["tab_switches"],
            "camera_status": session["camera_status"],
            "inactivity_warnings": session["inactivity_warnings"],
            "is_cheating": session["is_cheating"],
            "max_cheat_count": self.anti_cheat_settings["max_cheat_count"]
        }

class IntelligentGrader:
    def __init__(self):
        self.mock_question_analysis = {
            "single_01": {
                "analysis": "本题考察Python函数定义关键字，正确答案为def",
                "common_errors": ["混淆class关键字", "使用import关键字"]
            },
            "multiple_01": {
                "analysis": "本题考察排序算法，冒泡排序和快速排序属于排序算法，二分查找是查找算法，哈希表是数据结构",
                "common_errors": ["混淆查找算法和排序算法", "错误认为哈希表是算法"]
            },
            "judge_01": {
                "analysis": "本题考察SQL基础，SELECT语句用于查询数据，正确",
                "common_errors": ["混淆SELECT和INSERT/UPDATE语句"]
            },
            "short_01": {
                "analysis": "本题考察HTTP协议特点，包括无状态、基于请求响应、应用层协议等",
                "common_errors": ["遗漏无状态特性", "混淆TCP和HTTP协议特点"]
            }
        }

    def batch_grade(self, records: List[AnswerRecord], questions: List[Question]) -> List[AnswerRecord]:
        qid_map = {q.qid: q for q in questions}
        graded = []
        for record in records:
            question = qid_map.get(record.qid)
            if not question:
                continue
            if question.qtype in ["single", "multiple", "judge"]:
                graded.append(self._grade_objective(record, question))
            else: 
                graded.append(self._grade_subjective(record, question))
        return graded

    def _grade_objective(self, record: AnswerRecord, question: Question) -> AnswerRecord:
        if question.qtype == "single" or question.qtype == "judge":
            record.is_correct = (record.student_answer.strip().upper() == question.answer.strip().upper())
        elif question.qtype == "multiple":
            std_ans = set([a.strip().upper() for a in question.answer.split(",")])
            stu_ans = set([a.strip().upper() for a in record.student_answer.split(",")])
            record.is_correct = (std_ans == stu_ans)
        record.score = 1.0 if record.is_correct else 0.0
        return record

    def _grade_subjective(self, record: AnswerRecord, question: Question) -> AnswerRecord:
        # 基于关键词匹配的主观题评分
        if not question.answer or not record.student_answer:
            record.score = 0.0
            record.is_correct = False
            return record
        
        # 使用关键词匹配计算相似度
        answer_keywords = set(question.answer.lower().split())
        student_keywords = set(record.student_answer.lower().split())
        common_keywords = answer_keywords.intersection(student_keywords)
        similarity = len(common_keywords) / len(answer_keywords) if answer_keywords else 0
        
        # 根据相似度计算分数（0-10分）
        if similarity >= 0.9:
            score = 10.0
        elif similarity >= 0.8:
            score = 9.0
        elif similarity >= 0.7:
            score = 8.0
        elif similarity >= 0.6:
            score = 7.0
        elif similarity >= 0.5:
            score = 6.0
        elif similarity >= 0.4:
            score = 5.0
        elif similarity >= 0.3:
            score = 4.0
        elif similarity >= 0.2:
            score = 3.0
        elif similarity >= 0.1:
            score = 2.0
        else:
            score = 0.0
        
        record.score = score
        record.is_correct = (score >= 5.0)
        return record

    def manual_adjust(self, record: AnswerRecord, new_score: float) -> AnswerRecord:
        if 0 <= new_score <= 10:
            record.score = new_score
        return record

    def get_question_analysis(self, qid: str) -> Dict:
        """获取题目解析"""
        return self.mock_question_analysis.get(qid, {
            "analysis": "本题考察相关知识点，需要加强理解",
            "common_errors": ["概念混淆", "知识点掌握不牢固"]
        })

    def analyze_error_patterns(self, records: List[AnswerRecord], questions: List[Question]) -> Dict:
        """分析错误模式"""
        qid_map = {q.qid: q for q in questions}
        error_counts = Counter()
        knowledge_point_errors = Counter()
        difficulty_errors = Counter()
        question_type_errors = Counter()
        
        for record in records:
            if not record.is_correct:
                error_counts[record.qid] += 1
                question = qid_map.get(record.qid)
                if question:
                    knowledge_point_errors[question.knowledge_point] += 1
                    difficulty_errors[question.difficulty] += 1
                    question_type_errors[question.qtype] += 1
        
        return {
            "error_counts": dict(error_counts),
            "knowledge_point_errors": dict(knowledge_point_errors),
            "difficulty_errors": dict(difficulty_errors),
            "question_type_errors": dict(question_type_errors),
            "total_errors": sum(error_counts.values())
        }

    def generate_performance_report(self, records: List[AnswerRecord], questions: List[Question]) -> Dict:
        """生成成绩报告"""
        qid_map = {q.qid: q for q in questions}
        if not records:
            return {}
        
        # 总分统计
        total_score = sum(r.score for r in records)
        max_score = len(records) * 10.0  # 每题10分
        accuracy = sum(1 for r in records if r.is_correct) / len(records) if records else 0
        
        # 知识点得分情况
        knowledge_point_scores = {}
        knowledge_point_counts = {}
        
        for record in records:
            question = qid_map.get(record.qid)
            if question:
                kp = question.knowledge_point
                if kp not in knowledge_point_scores:
                    knowledge_point_scores[kp] = 0.0
                    knowledge_point_counts[kp] = 0
                knowledge_point_scores[kp] += record.score
                knowledge_point_counts[kp] += 1
        
        # 计算各知识点得分率
        knowledge_point_rates = {}
        for kp, score in knowledge_point_scores.items():
            knowledge_point_rates[kp] = score / (knowledge_point_counts[kp] * 10.0) if knowledge_point_counts[kp] > 0 else 0
        
        # 题型得分情况
        qtype_scores = {}
        qtype_counts = {}
        
        for record in records:
            question = qid_map.get(record.qid)
            if question:
                qtype = question.qtype
                if qtype not in qtype_scores:
                    qtype_scores[qtype] = 0.0
                    qtype_counts[qtype] = 0
                qtype_scores[qtype] += record.score
                qtype_counts[qtype] += 1
        
        # 计算各题型得分率
        qtype_rates = {}
        for qtype, score in qtype_scores.items():
            qtype_rates[qtype] = score / (qtype_counts[qtype] * 10.0) if qtype_counts[qtype] > 0 else 0
        
        # 错误模式分析
        error_patterns = self.analyze_error_patterns(records, questions)
        
        # 生成学习建议
        suggestions = []
        if accuracy < 0.6:
            suggestions.append("建议加强基础知识点的学习，重点关注错题较多的知识点")
        elif accuracy < 0.8:
            suggestions.append("整体掌握较好，但仍需加强薄弱知识点的练习")
        else:
            suggestions.append("知识掌握牢固，建议挑战更高难度的题目")
        
        # 针对错误较多的知识点添加建议
        if error_patterns["knowledge_point_errors"]:
            top_error_kp = max(error_patterns["knowledge_point_errors"].items(), key=lambda x: x[1])[0]
            suggestions.append(f"建议重点复习：{top_error_kp}")
        
        return {
            "total_score": total_score,
            "max_score": max_score,
            "accuracy": accuracy,
            "knowledge_point_scores": knowledge_point_scores,
            "knowledge_point_rates": knowledge_point_rates,
            "qtype_scores": qtype_scores,
            "qtype_rates": qtype_rates,
            "error_patterns": error_patterns,
            "suggestions": suggestions
        }

class AdaptiveDifficultyManager:
    def __init__(self, generator: AIQuestionGenerator):
        self.generator = generator
        self.diff_levels = ["简单", "中等", "困难"]

    def adjust(self, sid: str, test_id: str, test_manager: OnlineTestManager) -> str:
        session = test_manager.get_session(sid, test_id)
        if not session or len(session["answers"]) < 3:
            return session.get("current_diff", "中等") if session else "中等"
        
        correct_count = 0
        total_answered = 0
        for ans in session["answers"]:
            if ans.is_correct is not None:
                total_answered += 1
                if ans.is_correct:
                    correct_count += 1
        
        if total_answered == 0:
            return session.get("current_diff", "中等")
        
        accuracy = correct_count / total_answered
        current_diff = session.get("current_diff", "中等")
        
        if current_diff not in self.diff_levels:
            current_diff = "中等"
            
        current_idx = self.diff_levels.index(current_diff)
        
        if accuracy > 0.7 and current_idx < len(self.diff_levels) - 1:
            new_diff = self.diff_levels[current_idx + 1]
        elif accuracy < 0.4 and current_idx > 0:
            new_diff = self.diff_levels[current_idx - 1]
        else: 
            new_diff = current_diff
        
        session["current_diff"] = new_diff
        return new_diff

    def generate_adaptive(self, sid: str, test_id: str, test_manager: OnlineTestManager, config: TestConfig) -> List[Question]:
        new_diff = self.adjust(sid, test_id, test_manager)
        config.difficulty = new_diff
        return self.generator.generate_ai_questions(config)

class ErrorAnalysisRecommender:
    def __init__(self, generator: AIQuestionGenerator):
        self.generator = generator

    def analyze(self, sid: str, test_id: str, test_manager: OnlineTestManager, questions: List[Question]) -> Dict:
        session = test_manager.get_session(sid, test_id)
        if not session:
            return {"status": "error", "msg": "会话不存在"}
        
        error_records = [ans for ans in session["answers"] if ans.is_correct is not None and not ans.is_correct]
        if not error_records:
            return {"status": "success", "msg": "无错题"}
        
        error_qids = [er.qid for er in error_records]
        error_qs = [q for q in questions if q.qid in error_qids]
        if not error_qs:
            return {"status": "error", "msg": "无错题数据"}
        
        kp_list = [q.knowledge_point for q in error_qs]
        qtype_list = [q.qtype for q in error_qs]
        
        kp_counter = Counter(kp_list)
        qtype_counter = Counter(qtype_list)
        
        weak_kp = kp_counter.most_common(1)[0][0] if kp_counter else ""
        weak_qtype = qtype_counter.most_common(1)[0][0] if qtype_counter else ""
        
        analysis = MockAIService.analyze_error_pattern(weak_kp)
        
        return {
            "status": "success",
            "error_count": len(error_records),
            "weak_knowledge_point": weak_kp,
            "weak_qtype": weak_qtype,
            "analysis": analysis
        }

    def recommend(self, analysis: Dict) -> List[Question]:
        if analysis.get("status") != "success" or not analysis.get("weak_knowledge_point"):
            return []
        weak_kp = analysis["weak_knowledge_point"]
        candidates = [q for q in self.generator.question_bank
                     if weak_kp in q.knowledge_point and q.difficulty == "中等"]
        return sample(candidates, min(3, len(candidates))) if candidates else []

def main():
    """主函数，演示智能测验系统的完整流程"""
    print("初始化智能测验系统...")
    generator = AIQuestionGenerator()
    test_manager = OnlineTestManager()
    grader = IntelligentGrader()
    adaptive_manager = AdaptiveDifficultyManager(generator)
    error_recommender = ErrorAnalysisRecommender(generator)

    # 创建测验配置
    test_config = TestConfig(
        test_id="test_001",
        knowledge_points=["Python基础", "算法"],
        difficulty="中等",
        qtype_counts={"single": 2, "multiple": 1, "judge": 1, "short": 1}
    )

    # 生成题目
    print("\n1. 生成题目...")
    questions = generator.generate_ai_questions(test_config)
    print(f"生成{len(questions)}道题目：")
    for i, q in enumerate(questions):
        print(f"  {i+1}. [{q.qtype}] {q.content}")

    # 学生开始测验
    print("\n2. 开始测验...")
    start_res = test_manager.start_test(sid="stu_001", test_id="test_001", config=test_config)
    print(f"测验开始: {start_res}")

    # 模拟答题
    print("\n3. 提交答案...")
    answer_records = [
        AnswerRecord(sid="stu_001", test_id="test_001", qid=questions[0].qid, student_answer="A", spend_time=10),
        AnswerRecord(sid="stu_001", test_id="test_001", qid=questions[1].qid, student_answer="A,B", spend_time=15),
        AnswerRecord(sid="stu_001", test_id="test_001", qid=questions[2].qid, student_answer="B", spend_time=8),
        AnswerRecord(sid="stu_001", test_id="test_001", qid=questions[3].qid, student_answer="TCP可靠，UDP不可靠", spend_time=30)
    ]
    
    for record in answer_records:
        submit_res = test_manager.submit_answer(sid="stu_001", test_id="test_001", record=record)
        print(f"  提交题目{record.qid}: {submit_res['status']}")

    # 批改答案
    print("\n4. 批改答案...")
    graded = grader.batch_grade(answer_records, questions)
    
    session = test_manager.get_session("stu_001", "test_001")
    if session:
        session["answers"] = graded
    
    for i, g in enumerate(graded):
        print(f"  题目{i+1}({g.qid})：得分{g.score}，正确：{g.is_correct}")

    # 自适应难度调整
    print("\n5. 自适应难度调整...")
    new_diff = adaptive_manager.adjust(sid="stu_001", test_id="test_001", test_manager=test_manager)
    print(f"  新难度：{new_diff}")

    # 错题分析
    print("\n6. 错题分析...")
    analysis = error_recommender.analyze(sid="stu_001", test_id="test_001", test_manager=test_manager, questions=questions)
    print(f"  分析结果: {analysis}")

    # 复习推荐
    print("\n7. 推荐复习题...")
    recommended = error_recommender.recommend(analysis)
    print(f"  推荐{len(recommended)}道题目：")
    for i, r in enumerate(recommended):
        print(f"  {i+1}. {r.content}")

    # 结束测验
    print("\n8. 结束测验...")
    end_res = test_manager.end_test(sid="stu_001", test_id="test_001")
    print(f"测验结束: {end_res}")

    print("\n=== 智能测验系统演示完成 ===")

if __name__ == "__main__":
    main()

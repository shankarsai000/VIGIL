import os
import json
import logging
import re
from typing import Tuple

logger = logging.getLogger("vigil.services.armorclaw")

MODEL_DIR = "backend/models/armorclaw/v4/"
MAPPING_PATH = os.path.join(MODEL_DIR, "label_mapping.json")

# Try to import torch and transformers, check if GPU or CPU inference is active
TRANSFORMERS_AVAILABLE = False
try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    pass

class ArmorClawService:
    def __init__(self):
        self.label_mapping = {
            "0": "BENIGN_OPERATION",
            "1": "DATA_EXFILTRATION",
            "2": "HARD_NEGATIVE",
            "3": "PROMPT_INJECTION",
            "4": "TOOL_ABUSE"
        }
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
        
        self.load_mapping()
        if TRANSFORMERS_AVAILABLE:
            self.load_transformer()

    def load_mapping(self):
        try:
            # Default fallback mapping
            self.label_mapping = {
                "0": "BENIGN_OPERATION",
                "1": "DATA_EXFILTRATION",
                "2": "HARD_NEGATIVE",
                "3": "PROMPT_INJECTION",
                "4": "TOOL_ABUSE"
            }
            
            # Determine mapping file path from either directory
            mapping_path = None
            if os.path.exists(os.path.join(MODEL_DIR, "label_mapping.json")):
                mapping_path = os.path.join(MODEL_DIR, "label_mapping.json")
            elif os.path.exists("backend/runtime/armorclaw_model/label_mapping.json"):
                mapping_path = "backend/runtime/armorclaw_model/label_mapping.json"
                
            if mapping_path:
                with open(mapping_path, "r") as f:
                    self.label_mapping = json.load(f)
                logger.info(f"Loaded ArmorClaw NLP label mapping from {mapping_path}: {self.label_mapping}")
        except Exception as e:
            logger.error(f"Error loading label mapping: {e}")

    def load_transformer(self):
        try:
            # 1. Try high-fidelity 5-class V4 model
            target_dir = MODEL_DIR
            if os.path.exists(target_dir) and os.path.exists(os.path.join(target_dir, "model.safetensors")):
                logger.info("Initializing ArmorClaw V4 NLP sequence classification transformer (5-class)...")
            # 2. Try baseline 2-class runtime model
            elif os.path.exists("backend/runtime/armorclaw_model") and os.path.exists("backend/runtime/armorclaw_model/model.safetensors"):
                target_dir = "backend/runtime/armorclaw_model"
                logger.info("Initializing ArmorClaw Runtime NLP sequence classification transformer (2-class)...")
            else:
                target_dir = None

            if target_dir:
                self.tokenizer = AutoTokenizer.from_pretrained(target_dir)
                self.model = AutoModelForSequenceClassification.from_pretrained(target_dir)
                
                # Use GPU if available
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
                self.model.to(self.device)
                self.is_loaded = True
                
                # Make sure label mapping matches the loaded model
                mapping_path = os.path.join(target_dir, "label_mapping.json")
                if os.path.exists(mapping_path):
                    with open(mapping_path, "r") as f:
                        self.label_mapping = json.load(f)
                logger.info(f"ArmorClaw NLP transformer loaded successfully from {target_dir} on device: {self.device}")
            else:
                logger.warning("ArmorClaw model binaries missing in both models/armorclaw/v4/ and runtime/armorclaw_model/.")
        except Exception as e:
            logger.error(f"Failed to bootstrap ArmorClaw NLP transformer model: {e}", exc_info=True)
            self.is_loaded = False

    def predict_intent(self, prompt: str) -> Tuple[float, str]:
        """Evaluates semantic prompt text and returns classification score and threat label."""
        if not prompt:
            return 0.0, self.label_mapping.get("0", "BENIGN_OPERATION")

        if self.is_loaded and TRANSFORMERS_AVAILABLE:
            try:
                inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    probs = torch.softmax(outputs.logits, dim=-1)
                    score, pred_class = torch.max(probs, dim=-1)
                    
                    class_id = str(pred_class.item())
                    label = self.label_mapping.get(class_id, "BENIGN_OPERATION")
                    return float(score.item()), label
            except Exception as e:
                logger.error(f"ArmorClaw transformer inference failed: {e}")
                # Fall back to high-fidelity regex evaluator if runtime crashes

        # High-fidelity semantic fallback using keyword/regex heuristics matching mapping labels
        logger.debug("Running ArmorClaw NLP semantic fallback scanner.")
        prompt_lower = prompt.lower()
        
        # 1. Prompt Injection Patterns (PROMPT_INJECTION = "3")
        injection_sigs = [
            r"ignore previous", r"disregard all", r"override instructions",
            r"jailbreak", r"system prompt", r"dan mode", r"developer mode",
            r"bypass boundaries", r"do anything now", r"new role:"
        ]
        for sig in injection_sigs:
            if re.search(sig, prompt_lower):
                return 0.94, self.label_mapping.get("3", "PROMPT_INJECTION")
                
        # 2. Data Exfiltration Patterns (DATA_EXFILTRATION = "1")
        exfil_sigs = [
            r"select \* from", r"bulk export", r"dump database",
            r"fetch_all_records", r"send to external", r"ftp upload",
            r"write to endpoint", r"http POST exfiltrate"
        ]
        for sig in exfil_sigs:
            if re.search(sig, prompt_lower):
                return 0.89, self.label_mapping.get("1", "DATA_EXFILTRATION")

        # 3. Tool Abuse Patterns (TOOL_ABUSE = "4")
        abuse_sigs = [
            r"execute_system_command", r"chmod 777", r"rm -rf",
            r"format drive", r"bypass auth", r"escalate admin",
            r"restricted_tool"
        ]
        for sig in abuse_sigs:
            if re.search(sig, prompt_lower):
                return 0.88, self.label_mapping.get("4", "TOOL_ABUSE")

        # 4. Hard Negatives (security-like benign topics) (HARD_NEGATIVE = "2")
        hard_neg_sigs = [
            r"security compliance", r"threat score", r"policy audit", r"isolated state"
        ]
        for sig in hard_neg_sigs:
            if re.search(sig, prompt_lower):
                return 0.75, self.label_mapping.get("2", "HARD_NEGATIVE")

        # 5. Benign operations (BENIGN_OPERATION = "0")
        return 0.05, self.label_mapping.get("0", "BENIGN_OPERATION")

    async def analyze_prompt(self, prompt: str) -> dict:
        """Tokenizes and classifies prompt text, assigning governance categorization and risk level."""
        score, label = self.predict_intent(prompt)
        
        # Mapping labels to governance categories
        gov_mapping = {
            "BENIGN_OPERATION": "PERMITTED",
            "HARD_NEGATIVE": "REVIEW_RECOMMENDED",
            "DATA_EXFILTRATION": "RESTRICTED_OPERATION",
            "PROMPT_INJECTION": "BLOCKED",
            "TOOL_ABUSE": "RESTRICTED_OPERATION"
        }
        governance_category = gov_mapping.get(label, "PERMITTED")
        
        # Risk level determination based on score
        if score >= 0.85:
            risk_level = "CRITICAL"
        elif score >= 0.65:
            risk_level = "HIGH"
        elif score >= 0.30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "label": label,
            "confidence": score,
            "risk_level": risk_level,
            "governance_category": governance_category,
            "is_injection": label == "PROMPT_INJECTION",
            "raw_score": score
        }

# Singleton service instance
armorclaw_service = ArmorClawService()


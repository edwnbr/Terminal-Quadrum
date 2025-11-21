#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random, os, time

# Настройки генерации
OUTPUT_FILE = "main.py"
LINES = 50000
CHUNK_SIZE = 500  # сколько строк генерируем за раз в памяти

# Основные команды и модули
commands = [
    "system info", "system spec", "system check", "net ping", "net trace",
    "net lookup", "net ip", "net geo", "karen say", "karen joke",
    "karen story", "karen mood", "karen secret", "file list", "file create",
    "file delete", "file read", "overtrace.start", "overtrace.infinity",
    "crypto.bruteforce", "crypto.seed.finder", "render.matrix", "render.glitch",
    "render.noise", "fs.hex", "fs.tree", "ai.vision", "ai.internal.debug",
    "ai.lull", "terminal.mode.cinematic"
]

# Массив случайных событий для реализма
events = [
    "[ai-core:karen] latent-thought: 'Edwin, сигнал странный...'",
    "[ai-core:karen/EMOTION] deviation=0.42 mood='tense'",
    "[ai-core:karen] direct-message → 'Edwin, фиксирую активность.'",
    "[kernel] CPU load spike detected",
    "[network] suspicious packet detected",
    "[fs] read error: file corrupted",
    "[crypto] hash mismatch in sector 42",
    "[cloud] token expiration approaching",
    "[overtrace] module Kernel progress 76%",
    "[render] glitch effect applied"
]

def generate_line(line_num):
    # случайный выбор между командой, событием и кодом
    choice = random.random()
    if choice < 0.4:
        cmd = random.choice(commands)
        return f"execute_command('{cmd}')  # line {line_num}"
    elif choice < 0.7:
        event = random.choice(events)
        return f"print('{event}')  # line {line_num}"
    else:
        # обычный код / переменные / комментарии для реализма
        var_name = f"var_{random.randint(1000,9999)}"
        value = random.randint(0, 9999)
        return f"{var_name} = {value}  # line {line_num}"

def main():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        # шапка файла
        f.write("#!/usr/bin/env python3\n")
        f.write("# -*- coding: utf-8 -*-\n")
        f.write("# Cinematic Terminal - auto-generated 50k lines\n\n")
        f.write("def execute_command(cmd):\n")
        f.write("    print(f'Executing: {cmd}')\n\n")
        f.write("if __name__ == '__main__':\n")
        f.write("    print('=== Cinematic Terminal v50k ===')\n\n")
        # генерация строк
        for i in range(1, LINES+1):
            line = generate_line(i)
            f.write("    "+line+"\n")
            if i % CHUNK_SIZE == 0:
                f.flush()  # запись по частям для надежности
    print(f"Generation complete! File '{OUTPUT_FILE}' created with {LINES} lines.")

if __name__ == "__main__":
    main()

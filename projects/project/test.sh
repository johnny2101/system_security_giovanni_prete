#!/bin/bash

# Interrompe lo script se un comando fallisce
set -e 

# Colori per un output leggibile
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}   C-FLAT Automated Profiling & Enforcement Pipeline  ${NC}"
echo -e "${CYAN}======================================================${NC}\n"

# --- FASE 1: ESTRAZIONE STATICA ---
echo -e "${GREEN}[1/7] Compilazione LLVM Pass...${NC}"
cd llvm-pass
make clean; make
cd ..

echo -e "${GREEN}[2/7] Pulizia e Compilazione App (Estrazione CFG Statico)...${NC}"
make clean
make app
if [ ! -f cfa_policy.json ]; then
    echo -e "${RED}Errore: cfa_policy.json non generato!${NC}"
    exit 1
fi

# --- FASE 2: PREPARAZIONE MONITOR ---
echo -e "${GREEN}[3/7] Generazione policy.h dal CFG parziale...${NC}"
python3 app/policy_to_consts.py

echo -e "${GREEN}[4/7] Compilazione Sistema (Monitor in Profiler Mode)...${NC}"
make

# --- FASE 3: PROFILAZIONE DINAMICA ---
echo -e "${GREEN}[5/7] Esecuzione su QEMU (Learning Mode)...${NC}"
echo -e "${YELLOW}Nota: QEMU verrà terminato in automatico dopo 5 secondi.${NC}"
# Rimuove il log precedente
rm -f qemu.log
# Usa timeout per chiudere QEMU in automatico. '|| true' evita che 'set -e' blocchi lo script quando timeout forza l'uscita
gtimeout 5s make qemu 2>&1 | tee qemu.log || true

# --- FASE 4: MERGING ---
echo -e "${GREEN}[6/7] Fusione degli archi dinamici nel CFG statico...${NC}"
if grep -q "\[DYNAMIC_EDGE_DISCOVERED\]" qemu.log; then
    python3 merge_cfg.py cfa_policy.json qemu.log
    echo -e "${GREEN}Nuovi archi fusi con successo nel JSON.${NC}"
else
    echo -e "${YELLOW}Nessun nuovo arco dinamico rilevato in questo run.${NC}"
fi

# --- FASE 5: BLINDATURA (ENFORCEMENT) ---
echo -e "${GREEN}[7/7] Ricompilazione Sistema (Enforcement Mode)...${NC}"
# Rigenera l'header C con il JSON completo
python3 app/policy_to_consts.py
# Ricompila il kernel/monitor
make clean
make

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}   Pipeline Completata! Il sistema è ora BLINDATO.    ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "Puoi testare la versione finale eseguendo manualmente: ${YELLOW}make qemu${NC}"
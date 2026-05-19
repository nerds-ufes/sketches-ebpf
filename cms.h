#pragma once

#define CMS_ROWS  2      // número de funções hash
#define CMS_COLS  32   // buckets por linha (potência de 2)
#define CMS_SEED  0xdeadbeef

// Índice na matriz: row * CMS_COLS + col
#define CMS_INDEX(row, col) ((row) * CMS_COLS + (col))
#define CMS_TOTAL (CMS_ROWS * CMS_COLS)
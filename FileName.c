#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int cpu;
    int ram;
    int disk;
} resource_values;

resource_values set_check_values();
void read_log_file(const wchar_t* filename, resource_values* values, int* count);
void analyze_statistics(resource_values* values, int count);
void monitor_resources(resource_values* values, int count, resource_values limits);
void extract_values_from_line(const wchar_t* line, resource_values* values);
int compare_alert_levels(resource_values values, resource_values limits);
void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count);
void save_results(const wchar_t* filename, wchar_t threats[][256], int threats_count);

int main() {
    setlocale(LC_CTYPE, ""); // Установка локали
    wchar_t filename[256];
    int choice;

    resource_values limits = { 0, 0, 0 };

    do {
        printf("Выберите необходимую функцию:\n");
        printf("1) Указать пороговые значения\n");
        printf("2) Мониторинг\n");
        printf("3) Анализ лог-файла\n");
        printf("Для выхода из программы нажмите на 0\n");
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("Введите имя лог-файла для мониторинга: ");
            wscanf(L"%ls", filename);
            resource_values values[100];
            int count = 0;
            read_log_file(filename, values, &count);
            monitor_resources(values, count, limits);
            break;
        case 3:
            printf("Введите имя лог-файла для анализа: ");
            wscanf(L"%ls", filename);
            resource_values values_for_analysis[100];
            int count_analysis = 0;
            read_log_file(filename, values_for_analysis, &count_analysis);
            analyze_statistics(values_for_analysis, count_analysis);
            break;
        case 0:
            break;
        default:
            printf("Нет такой функции.\n");
        }
    } while (choice != 0);
    return 0;
}

resource_values set_check_values() {
    resource_values thresholds;
    printf("Введите пороговое значение для загрузки процессора (0-100): ");
    scanf("%d", &thresholds.cpu);
    printf("Введите пороговое значение для загрузки оперативной памяти (0-100): ");
    scanf("%d", &thresholds.ram);
    printf("Введите пороговое значение для загрузки дискового пространства (0-100): ");
    scanf("%d", &thresholds.disk);
    printf("Пороговые значения установлены.\n");
    return thresholds;
}

void read_log_file(const wchar_t* filename, resource_values* values, int* count) {
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("Не удалось открыть файл");
        exit(EXIT_FAILURE);
    }

    wchar_t line[256]; // Буфер для строки
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        extract_values_from_line(line, &values[*count]);
        (*count)++;
    }

    fclose(log_file);
}

void monitor_resources(resource_values* values, int count, resource_values limits) {
    wchar_t threats[100][256]; // Массив для хранения угроз
    int threats_count = 0; // Счетчик угроз

    for (int i = 0; i < count; i++) {
        int alert_level = compare_alert_levels(values[i], limits);
        if (alert_level > 0) {
            printf("Запись %d: ", i + 1);
            wprintf(L"Загрузка процессора: %d%%, Загрузка оперативной памяти: %d%%, Загрузка дискового пространства: %d%%\n",
                values[i].cpu, values[i].ram, values[i].disk);
            // Добавляем угрозу в массив
            analyze_threats(values[i], limits, threats, &threats_count);
        }
    }

    // Предложить сохранить результаты
    if (threats_count > 0) {
        printf("Вы хотите сохранить результаты мониторинга? (1 - Да, 0 - Нет): ");
        int save;
        scanf("%d", &save);
        if (save) {
            wchar_t output_filename[256];
            printf("Введите имя файла для сохранения: ");
            wscanf(L"%ls", output_filename);
            save_results(output_filename, threats, threats_count);
        }
    }
    else {
        printf("Нет угроз, ничего сохранять не нужно.\n");
    }
}

void analyze_statistics(resource_values* values, int count) {
    if (count == 0) {
        printf("Нет данных для анализа.\n");
        return;
    }

    int min_cpu = 100, min_ram = 100, min_disk = 100;
    int max_cpu = 0, max_ram = 0, max_disk = 0;
    int total_cpu = 0, total_ram = 0, total_disk = 0;

    for (int i = 0; i < count; i++) {
        if (values[i].cpu < min_cpu) min_cpu = values[i].cpu;
        if (values[i].ram < min_ram) min_ram = values[i].ram;
        if (values[i].disk < min_disk) min_disk = values[i].disk;

        if (values[i].cpu > max_cpu) max_cpu = values[i].cpu;
        if (values[i].ram > max_ram) max_ram = values[i].ram;
        if (values[i].disk > max_disk) max_disk = values[i].disk;

        total_cpu += values[i].cpu;
        total_ram += values[i].ram;
        total_disk += values[i].disk;
    }

    printf("Минимальная загрузка процессора: %d%%, оперативной памяти: %d%%, дискового пространства: %d%%\n", min_cpu, min_ram, min_disk);
    printf("Максимальная загрузка процессора: %d%%, оперативной памяти: %d%%, дискового пространства: %d%%\n", max_cpu, max_ram, max_disk);
    printf("Средняя загрузка процессора: %.2f%%, оперативной памяти: %.2f%%, дискового пространства: %.2f%%\n",
        (float)total_cpu / count, (float)total_ram / count, (float)total_disk / count);
}

int compare_alert_levels(resource_values values, resource_values limits) {
    return (values.cpu > limits.cpu) + (values.ram > limits.ram) + (values.disk > limits.disk);
}

void extract_values_from_line(const wchar_t* line, resource_values* values) {
    values->cpu = -1;
    values->ram = -1;
    values->disk = -1;

    wchar_t* cpu_str = wcsstr(line, L"Загрузка процессора");
    wchar_t* ram_str = wcsstr(line, L"Загрузка оперативной памяти");
    wchar_t* disk_str = wcsstr(line, L"Загрузка дискового пространства");

    if (cpu_str) {
        swscanf(cpu_str, L"Загрузка процессора = %d%%", &values->cpu);
    }
    if (ram_str) {
        swscanf(ram_str, L"Загрузка оперативной памяти = %d%%", &values->ram);
    }
    if (disk_str) {
        swscanf(disk_str, L"Загрузка дискового пространства = %d%%", &values->disk);
    }
}

void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count) {
    int alert_level = compare_alert_levels(values, limits);

    if (alert_level > 0) {
        wchar_t threat_level[20];
        switch (alert_level) {
        case 3:
            wcscpy(threat_level, L"ВЫСОКИЙ");
            break;
        case 2:
            wcscpy(threat_level, L"СРЕДНИЙ");
            break;
        case 1:
            wcscpy(threat_level, L"НИЗКИЙ");
            break;
        default:
            return; // Нормальное состояние, пропускаем
        }

        swprintf(threats[*threats_count], 256, L"Уровень угрозы: %ls, Загрузка процессора: %d%%, Загрузка оперативной памяти: %d%%, Загрузка дискового пространства: %d%%\n",
            threat_level, values.cpu, values.ram, values.disk);
        (*threats_count)++;
    }
}

void save_results(const wchar_t* filename, wchar_t threats[][256], int threats_count) {
    FILE* output_file = _wfopen(filename, L"w, ccs=UTF-8");
    if (!output_file) {
        perror("Не удалось открыть файл для записи");
        exit(EXIT_FAILURE);
    }

    printf("Выберите уровень угроз для сохранения:\n");
    printf("1 - ВЫСОКИЙ\n");
    printf("2 - СРЕДНИЙ\n");
    printf("3 - НИЗКИЙ\n");
    printf("Выберите вариант (1-3): ");

    int selected_level;
    scanf("%d", &selected_level);

    for (int i = 0; i < threats_count; i++) {
        switch (selected_level) {
        case 1:
            if (wcsstr(threats[i], L"ВЫСОКИЙ")) {
                fputws(threats[i], output_file);
            }
            break;
        case 2:
            if (wcsstr(threats[i], L"СРЕДНИЙ")) {
                fputws(threats[i], output_file);
            }
            break;
        case 3:
            if (wcsstr(threats[i], L"НИЗКИЙ")) {
                fputws(threats[i], output_file);
            }
            break;
        default:
            printf("Неверный уровень угрозы.\n");
            fclose(output_file);
            return; // Выходим из функции в случае неправильного уровня
        }
    }

    fclose(output_file);
    wprintf(L"Результаты мониторинга успешно сохранены в файл: '%ls'.\n", filename);
}
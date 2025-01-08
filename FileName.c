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
    setlocale(LC_CTYPE, ""); // ��������� ������
    wchar_t filename[256];
    int choice;

    resource_values limits = { 0, 0, 0 };

    do {
        printf("�������� ����������� �������:\n");
        printf("1) ������� ��������� ��������\n");
        printf("2) ����������\n");
        printf("3) ������ ���-�����\n");
        printf("��� ������ �� ��������� ������� �� 0\n");
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("������� ��� ���-����� ��� �����������: ");
            wscanf(L"%ls", filename);
            resource_values values[100];
            int count = 0;
            read_log_file(filename, values, &count);
            monitor_resources(values, count, limits);
            break;
        case 3:
            printf("������� ��� ���-����� ��� �������: ");
            wscanf(L"%ls", filename);
            resource_values values_for_analysis[100];
            int count_analysis = 0;
            read_log_file(filename, values_for_analysis, &count_analysis);
            analyze_statistics(values_for_analysis, count_analysis);
            break;
        case 0:
            break;
        default:
            printf("��� ����� �������.\n");
        }
    } while (choice != 0);
    return 0;
}

resource_values set_check_values() {
    resource_values thresholds;
    printf("������� ��������� �������� ��� �������� ���������� (0-100): ");
    scanf("%d", &thresholds.cpu);
    printf("������� ��������� �������� ��� �������� ����������� ������ (0-100): ");
    scanf("%d", &thresholds.ram);
    printf("������� ��������� �������� ��� �������� ��������� ������������ (0-100): ");
    scanf("%d", &thresholds.disk);
    printf("��������� �������� �����������.\n");
    return thresholds;
}

void read_log_file(const wchar_t* filename, resource_values* values, int* count) {
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("�� ������� ������� ����");
        exit(EXIT_FAILURE);
    }

    wchar_t line[256]; // ����� ��� ������
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        extract_values_from_line(line, &values[*count]);
        (*count)++;
    }

    fclose(log_file);
}

void monitor_resources(resource_values* values, int count, resource_values limits) {
    wchar_t threats[100][256]; // ������ ��� �������� �����
    int threats_count = 0; // ������� �����

    for (int i = 0; i < count; i++) {
        int alert_level = compare_alert_levels(values[i], limits);
        if (alert_level > 0) {
            printf("������ %d: ", i + 1);
            wprintf(L"�������� ����������: %d%%, �������� ����������� ������: %d%%, �������� ��������� ������������: %d%%\n",
                values[i].cpu, values[i].ram, values[i].disk);
            // ��������� ������ � ������
            analyze_threats(values[i], limits, threats, &threats_count);
        }
    }

    // ���������� ��������� ����������
    if (threats_count > 0) {
        printf("�� ������ ��������� ���������� �����������? (1 - ��, 0 - ���): ");
        int save;
        scanf("%d", &save);
        if (save) {
            wchar_t output_filename[256];
            printf("������� ��� ����� ��� ����������: ");
            wscanf(L"%ls", output_filename);
            save_results(output_filename, threats, threats_count);
        }
    }
    else {
        printf("��� �����, ������ ��������� �� �����.\n");
    }
}

void analyze_statistics(resource_values* values, int count) {
    if (count == 0) {
        printf("��� ������ ��� �������.\n");
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

    printf("����������� �������� ����������: %d%%, ����������� ������: %d%%, ��������� ������������: %d%%\n", min_cpu, min_ram, min_disk);
    printf("������������ �������� ����������: %d%%, ����������� ������: %d%%, ��������� ������������: %d%%\n", max_cpu, max_ram, max_disk);
    printf("������� �������� ����������: %.2f%%, ����������� ������: %.2f%%, ��������� ������������: %.2f%%\n",
        (float)total_cpu / count, (float)total_ram / count, (float)total_disk / count);
}

int compare_alert_levels(resource_values values, resource_values limits) {
    return (values.cpu > limits.cpu) + (values.ram > limits.ram) + (values.disk > limits.disk);
}

void extract_values_from_line(const wchar_t* line, resource_values* values) {
    values->cpu = -1;
    values->ram = -1;
    values->disk = -1;

    wchar_t* cpu_str = wcsstr(line, L"�������� ����������");
    wchar_t* ram_str = wcsstr(line, L"�������� ����������� ������");
    wchar_t* disk_str = wcsstr(line, L"�������� ��������� ������������");

    if (cpu_str) {
        swscanf(cpu_str, L"�������� ���������� = %d%%", &values->cpu);
    }
    if (ram_str) {
        swscanf(ram_str, L"�������� ����������� ������ = %d%%", &values->ram);
    }
    if (disk_str) {
        swscanf(disk_str, L"�������� ��������� ������������ = %d%%", &values->disk);
    }
}

void analyze_threats(resource_values values, resource_values limits, wchar_t threats[][256], int* threats_count) {
    int alert_level = compare_alert_levels(values, limits);

    if (alert_level > 0) {
        wchar_t threat_level[20];
        switch (alert_level) {
        case 3:
            wcscpy(threat_level, L"�������");
            break;
        case 2:
            wcscpy(threat_level, L"�������");
            break;
        case 1:
            wcscpy(threat_level, L"������");
            break;
        default:
            return; // ���������� ���������, ����������
        }

        swprintf(threats[*threats_count], 256, L"������� ������: %ls, �������� ����������: %d%%, �������� ����������� ������: %d%%, �������� ��������� ������������: %d%%\n",
            threat_level, values.cpu, values.ram, values.disk);
        (*threats_count)++;
    }
}

void save_results(const wchar_t* filename, wchar_t threats[][256], int threats_count) {
    FILE* output_file = _wfopen(filename, L"w, ccs=UTF-8");
    if (!output_file) {
        perror("�� ������� ������� ���� ��� ������");
        exit(EXIT_FAILURE);
    }

    printf("�������� ������� ����� ��� ����������:\n");
    printf("1 - �������\n");
    printf("2 - �������\n");
    printf("3 - ������\n");
    printf("�������� ������� (1-3): ");

    int selected_level;
    scanf("%d", &selected_level);

    for (int i = 0; i < threats_count; i++) {
        switch (selected_level) {
        case 1:
            if (wcsstr(threats[i], L"�������")) {
                fputws(threats[i], output_file);
            }
            break;
        case 2:
            if (wcsstr(threats[i], L"�������")) {
                fputws(threats[i], output_file);
            }
            break;
        case 3:
            if (wcsstr(threats[i], L"������")) {
                fputws(threats[i], output_file);
            }
            break;
        default:
            printf("�������� ������� ������.\n");
            fclose(output_file);
            return; // ������� �� ������� � ������ ������������� ������
        }
    }

    fclose(output_file);
    wprintf(L"���������� ����������� ������� ��������� � ����: '%ls'.\n", filename);
}
fontSize = 20
textFontSize = 16

figure_width = 1200;
figure_height = 600;

data_p224 = readmatrix('online_experiment_results/experiment_online_results_secp224r1.csv');
data_p256 = readmatrix('online_experiment_results/experiment_online_results_secp256k1.csv');
data_p384 = readmatrix('online_experiment_results/experiment_online_results_secp384r1.csv');
data_p521 = readmatrix('online_experiment_results/experiment_online_results_secp521r1.csv');
data_t571 = readmatrix('online_experiment_results/experiment_online_results_sect571r1.csv');
data_rsa1024 = readmatrix('online_experiment_results/experiment_online_results_rsa1024.csv');
data_rsa2048 = readmatrix('online_experiment_results/experiment_online_results_rsa2048.csv');
data_rsa4096 = readmatrix('online_experiment_results/experiment_online_results_rsa4096.csv');
data_dil2 = readmatrix('online_experiment_results/experiment_online_results_dilithium2.csv');
data_dil3 = readmatrix('online_experiment_results/experiment_online_results_dilithium3.csv');
data_dil5 = readmatrix('online_experiment_results/experiment_online_results_dilithium5.csv');
data_fal512 = readmatrix('online_experiment_results/experiment_online_results_falcon512.csv');
data_fal1024 = readmatrix('online_experiment_results/experiment_online_results_falcon1024.csv');
data_sph128f = readmatrix('online_experiment_results/experiment_online_results_sphincssha2128fsimple.csv');
data_sph128s = readmatrix('online_experiment_results/experiment_online_results_sphincssha2128ssimple.csv');
data_sph256f = readmatrix('online_experiment_results/experiment_online_results_sphincssha2256fsimple.csv');
data_sph256s = readmatrix('online_experiment_results/experiment_online_results_sphincssha2256ssimple.csv');

% 1 = Total Handshake Duration (ms)
% 2 = Hash Check Duration (ms)
% 3 = Data Check Duration (ms)
% 4 = Signature Check Duration (ms)
plotNum = 1

if plotNum == 1
    labelName = 'Total Handshake Duration (ms)'
    column = 2

elseif plotNum == 2
    labelName = 'Hash Check Duration (ms)'
    column = 3

elseif plotNum == 3
    labelName = 'Data Check Duration (ms)'
    column = 4

elseif plotNum == 4
    labelName = 'Signature Check Duration (ms)'
    column = 5
end

% Algorithms
algorithms = {
    "Secp224r1", "Secp256k1", "Secp384r1", "Secp521r1", "Sect571r1", "RSA 1024", "RSA 2048", "RSA 4096", ...
    "Dilithium 2", "Dilithium 3", "Dilithium 5", "Falcon 512", "Falcon 1024", "SPHINCS+ SHA2-128f", "SPHINCS+ SHA2-128s", "SPHINCS+ SHA2-256f", "SPHINCS+ SHA2-256s"
};


% Data
data = {
    data_p224, data_p256, data_p384, data_p521, data_t571, data_rsa1024, data_rsa2048, ...
    data_rsa4096, data_dil2, data_dil3, data_dil5, data_fal512, data_fal1024, ...
    data_sph128f, data_sph128s, data_sph256f, data_sph256s
};

% Compute averages
avg_values = cellfun(@(x) mean(x(:, column)), data);

% Compute confidence intervals
ci_values = cellfun(@(x) getConfidenceInterval(x(:, column)), data);

% Create bar plot
fig = figure;
% Set the figure width and height
set(fig, 'Position', [100, 100, 100+figure_width, 100+figure_height]);
hold on;
barh(1:length(algorithms), avg_values, 'FaceColor', '#DDD');
set(gca,'YDir','reverse');

% Set y labels and x label
yticks(1:length(algorithms));
yticklabels(algorithms);
xlabel(labelName, 'FontSize', fontSize);

set(gca,'FontSize', fontSize)

grid on;
grid minor;
set(gca, 'XMinorGrid', 'on', 'YMinorGrid', 'off');

% Display value for each bar using the 'text' function
padding = 0.5;
for i = 1:length(algorithms)
    text(avg_values(i) - ci_values(i) - padding, i, num2str(avg_values(i)), 'HorizontalAlignment', 'right', 'FontSize', textFontSize);
end

% Plot confidence intervals
for i = 1:length(algorithms)
    plotConfidenceInterval(avg_values(i), i, ci_values(i));
end


function CI = getConfidenceInterval(x)
    confidence_interval_percent=0.95;
    SEM = std(x)/sqrt(length(x)); % Standard Error
    df = length(x) - 1; % degrees of freedom
    tscore = tinv((1 + confidence_interval_percent)/2, df); % t-score for desired confidence level
    CI = tscore * SEM; 
    return;
end

function plotConfidenceInterval(x, y, yci)
    ci_color = 'black';
    ci_width = 0.1;
    line_thickness = 1;

    plot([x - yci, x + yci], [y, y], 'Color', ci_color, 'LineWidth', line_thickness, 'HandleVisibility','off');
    plot([x - yci, x - yci], [y - ci_width, y + ci_width], 'Color', ci_color, 'LineWidth', line_thickness, 'HandleVisibility','off');
    plot([x + yci, x + yci], [y - ci_width, y + ci_width], 'Color', ci_color, 'LineWidth', line_thickness, 'HandleVisibility','off');
end

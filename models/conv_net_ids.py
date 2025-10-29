import torch
from torch import nn

class ConvNetIDS(nn.Module):
    def __init__(self, sample_input: torch.Tensor, num_outputs: int = 1, number_of_channels = 1):
        super(ConvNetIDS, self).__init__()

        # --- Convolutional feature extractor ---
        self.feature_extraction_layer = nn.Sequential(
            nn.Conv2d(in_channels=number_of_channels, out_channels=32, kernel_size=5, stride=1, padding='same'),
            nn.ReLU(),
            nn.BatchNorm2d(32, eps=0.001, momentum=0.9),
            nn.MaxPool2d(kernel_size=2, stride=2),

            nn.Conv2d(in_channels=32, out_channels=64, kernel_size=5, stride=1, padding='same'),
            nn.ReLU(),
            nn.BatchNorm2d(64, eps=0.001, momentum=0.9),
            nn.MaxPool2d(kernel_size=2, stride=2)
        )

        # --- Dynamically infer flattened feature size ---
        with torch.no_grad():
            sample_output = self.feature_extraction_layer(sample_input)
            flattened_size = sample_output.view(sample_output.size(0), -1).size(1)

        # --- Classification layers ---
        self.binary_classification_layer_fc1 = nn.Sequential(
            nn.Dropout(p=0.3),
            nn.Linear(flattened_size, 64),
            nn.Dropout(p=0.3),
            nn.ReLU(),
        )

        self.binary_classification_layer_fc2 = nn.Sequential(
            nn.Linear(64, num_outputs)
        )

    def forward(self, x):
        x = self.feature_extraction_layer(x)
        x = torch.flatten(x, 1)
        x = self.binary_classification_layer_fc1(x)
        x = self.binary_classification_layer_fc2(x)
        x = torch.sigmoid(x)
        return x

    def cnn_forward(self, x):
        x = self.feature_extraction_layer(x)
        x = torch.flatten(x, 1)
        return x

    def fc1_forward(self, x):
        x = self.feature_extraction_layer(x)
        x = torch.flatten(x, 1)
        x = self.binary_classification_layer_fc1(x)
        return x

import argparse
import json
import torch

from feature_generator import generalized_cnn_ids_feature_generator
from feature_generator import cnn_ids_feature_generator
from models import (
    conv_net_ids,
    multiclass_conv_net_ids,
    pruned_conv_net_ids,
    sklearn_classifier,
    stacked_autoencoder_ids
)
from model_test import (
    pytorch_model_test,
    sklearn_model_test,
    autoencoder_model_test
)

AVAILABLE_FEATURE_GENERATORS = {
    "CNNIDSFeatureGenerator": cnn_ids_feature_generator.CNNIDSFeatureGenerator,
    "GeneralizedCNNIDSFeatureGenerator": generalized_cnn_ids_feature_generator.GeneralizedCNNIDSFeatureGenerator
}

AVAILABLE_IDS = {
    "CNNIDS": conv_net_ids.ConvNetIDS,
    "MultiClassCNNIDS": multiclass_conv_net_ids.MultiClassConvNetIDS,
    "PrunedCNNIDS": pruned_conv_net_ids.PrunedConvNetIDS,
    "SklearnClassifier": sklearn_classifier.SklearnClassifier,
    "Autoencoder": stacked_autoencoder_ids.StackedAutoencoderIDS
}

AVAILABLE_FRAMEWORKS = {
    "pytorch": pytorch_model_test.PytorchModelTest,
    "sklearn": sklearn_model_test.SklearnModelTest,
    "pytorch_autoencoder": autoencoder_model_test.PytorchAutoencoderTest
}

def main():
    print("Executing main function...")
    parser = argparse.ArgumentParser(description='Execute model train validation step')
    parser.add_argument('--model_test_config', required=True, help='JSON File containing the configs the model test procedure')
    args = parser.parse_args()

    try:
        with open(args.model_test_config, 'r') as model_test_config:
            model_test_config_dict = json.load(model_test_config)

    except FileNotFoundError as e:
        print(f"parse_args: Error: {e}")
    except json.JSONDecodeError as e:
        print(f"parse_args: Error decoding JSON: {e}")

    print("##### Loaded configuration files #####")
    print(json.dumps(model_test_config_dict, indent=4, sort_keys=True))

    feat_gen_config_dict = model_test_config_dict['feat_gen']
    model_specs_dict = model_test_config_dict['model_specs']

    feature_generator_name = feat_gen_config_dict['feature_generator']
    feature_generator_config = feat_gen_config_dict['config']
    feature_generator_load_paths = feat_gen_config_dict['load_paths']

    if feature_generator_name not in AVAILABLE_FEATURE_GENERATORS:
        raise KeyError(f"Selected feature generator: {feature_generator_name} is NOT available!")

    framework = model_specs_dict['framework']
    if framework not in AVAILABLE_FRAMEWORKS:
        raise KeyError(f"Selected framework: {framework} is NOT available!")

    model_name = model_specs_dict['model']
    if model_name not in AVAILABLE_IDS:
        raise KeyError(f"Selected model: {model_name} is NOT available!")

    print("> Loading features...")
    selected_feature_generator = AVAILABLE_FEATURE_GENERATORS[feature_generator_name](feature_generator_config)
    data = selected_feature_generator.load_features(feature_generator_load_paths)
    print(f"DEBUG: len(data) = {len(data)}")

    print("> Creating model...")
    if framework == "pytorch":
        # Take a single sample from the dataset
        sample_X, _ = data[0]  # first element (X[0], y[0])
        # Convert to torch tensor
        sample_tensor = torch.tensor(sample_X, dtype=torch.float32).unsqueeze(0)
        num_outputs = model_specs_dict.get('hyperparameters').get('num_outputs', 1)
        num_channels = model_specs_dict.get('hyperparameters').get('num_channels', 1)
        num_ensemble_inputs = model_specs_dict.get('hyperparameters').get('ensemble_inputs', 2)
        if model_name in ["CNNIDS", "PrunedCNNIDS", "MultiClassCNNIDS"]:
            if num_outputs > 1:
                model = AVAILABLE_IDS[model_name](sample_input=sample_tensor, number_of_outputs=num_outputs, number_of_channels=num_channels)
            else:
                model = AVAILABLE_IDS[model_name](sample_input=sample_tensor, number_of_channels=num_channels)
        print(f">> {model_name} was created with {num_outputs} outputs")
        
    elif framework == "sklearn":
        model = AVAILABLE_IDS[model_name](model_specs_dict)
        
    elif framework == "pytorch_autoencoder":
        sample_X, _ = data[0]  # first element (X[0], y[0])
        input_shape = sample_X.shape
        model = AVAILABLE_IDS[model_name](input_shape=input_shape,latent_dim=model_specs_dict["hyperparameters"]["latent_dim"])

    print("> Initializing model test...")
    test = AVAILABLE_FRAMEWORKS[framework](model, model_test_config_dict)
    test.execute(data, train_errors_path=model_specs_dict["train_errors_path"])

    print("Model tested successfully!")

if __name__ == "__main__":
    main()

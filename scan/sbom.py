import datetime
import json
import logging
from enum import Enum

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.model.bom import Bom
from cyclonedx.schema import SchemaVersion
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.model import Property

logger = logging.getLogger(__name__)


class DependencyType (Enum):
    DEV = "dev"
    PROD = "prod"


class Package:
    def __init__(self, name: str, version: str, source: str, type: DependencyType) -> None:
        self.name = name
        self.version = version
        self.source = set([source])  # This is a list of strings
        self.type = set([type])

    def __hash__(self):
        # Hash based on the name and version concatenated
        return hash(f"{self.name}=={self.version}")

    def __eq__(self, other):
        # Equality based on name and version
        if not isinstance(other, Package):
            return NotImplemented
        return self.name == other.name and self.version == other.version

    def add_source(self, source):
        self.source.add(source)

    def add_type(self, type):
        self.source.add(type)

    def __repr__(self):
        return f"{self.name}=={self.version} Source:({', '.join(self.source)}) Type:({', '.join([t.value for t in self.type])})"

    def component(self):
        # Convert this package into a component for the SBOM
        component = Component(
            name=self.name,
            version=self.version,
            type=ComponentType.LIBRARY,
            properties=[
                Property(name="source", value=", ".join(self.source)),
                Property(name="type", value=", ".join([t.value for t in self.type]))
            ]
        )

        return component


class PackageCollection:
    def __init__(self):
        self.packages = {}

    def add(self, name, version, source, type):
        key = f"{name}=={version}"
        if key in self.packages:
            self.packages[key].add_source(source)
            self.packages[key].add_type(source)
        else:
            self.packages[key] = Package(name, version, source, type)

    def add_list(self, packages, source, type):
        for package in packages:
            self.add(package["name"], package["version"], source, type)

    def __repr__(self):
        return "\n".join([str(package) for package in self.packages.values()])

    def create_sbom(self):

        # Create an empty cyclonedx SBOM
        bom = Bom()
        bom.schema_version = SchemaVersion.V1_3
        bom.metadata.timestamp = datetime.datetime.now()

        # Add all packages to the SBOM
        bom.components = [package.component() for package in self.packages.values()]

        return bom

    def create_sbom_dict(self):
        sbom = self.create_sbom()
        my_json_outputter: 'JsonOutputter' = JsonV1Dot5(sbom)
        serialized_json = my_json_outputter.output_as_string(indent=2)

        try:
            my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)
            validation_errors = my_json_validator.validate_str(serialized_json)
            if validation_errors:
                logger.error('JSON invalid', 'ValidationError:', repr(validation_errors), sep='\n')
                raise Exception('JSON invalid')
        except MissingOptionalDependencyException as error:
            logger.error('JSON-validation was skipped due to', error)

        return json.loads(serialized_json)

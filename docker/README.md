# Docker

## Images

This project provides three Docker images:

- **`holod`**: Runs the Holo daemon only.
- **`holo-cli`**: Includes the CLI tool for managing `holod` instances (maintained in a separate repository).
- **`holo-bundle`**: All-in-one image with `holod`, `holo-cli`, and additional network tools. Useful for testing and development.

## Building

From the root of the repository, build one of the images by running the appropriate command:

### Build the `holod` image

Command:
```sh
DOCKER_BUILDKIT=1 docker build -t holod -f docker/Dockerfile.holod .
```

By default, the build will use the `release` profile. If you want to build with a different profile, you can specify it using the `--build-arg` flag:
```sh
DOCKER_BUILDKIT=1 docker build --build-arg BUILD_PROFILE=dev -t holod -f docker/Dockerfile.holod .
```

Available build profiles:
- `release` (default): Optimized for production.
- `dev`: For development with debugging info.
- `small`: For smaller binaries.

### Build the `holo-bundle` image

Command:
```sh
DOCKER_BUILDKIT=1 docker build -t holo-bundle -f docker/Dockerfile.holo-bundle .
```

The `holo-bundle` build accepts two optional build arguments that specify which container images to pull the binaries from:
- `HOLOD_IMAGE` (default: `ghcr.io/holo-routing/holod:latest`)
- `HOLO_CLI_IMAGE` (default: `ghcr.io/holo-routing/holo-cli:latest`)

# Running

To run the container in the background, use the following command:
```sh
docker run -itd --privileged --name holo holo-bundle
```

To access Holo's CLI, use the following command:
```sh
docker exec -it holo holo-cli
```
